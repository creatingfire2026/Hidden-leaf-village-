"""
OpenClaw Tor P2P Node — Hub Agent
Symmetry Labs Infrastructure

Responsibilities:
  - Maintain a P2P peer table in Redis (Hub state bus)
  - Accept inbound connections via Tor hidden service (port 8765)
  - Route outbound connections through Tor SOCKS5 proxy
  - Expose Prometheus metrics on port 9090
  - Provide an AI-powered query interface via Anthropic Claude

Environment variables (all have defaults for local dev):
  OC_DATA_DIR             /var/lib/oc-tor-net
  OC_LOG_DIR              /var/log/oc-tor-net
  OC_HIDDEN_SERVICE_DIR   /var/lib/tor/hidden_service
  OC_AGENT_PORT           8765
  OC_METRICS_PORT         9090
  TOR_SOCKS_PROXY         socks5h://tor:9050
  REDIS_URL               redis://:changeme-in-production@redis:6379/0
  REDIS_PASSWORD_FILE     (path to file containing Redis password)
  REDIS_HOST              redis
  ANTHROPIC_API_KEY       (optional — AI features disabled when absent)
  ANTHROPIC_API_KEY_FILE  (path to file; takes precedence over env var)
  ANTHROPIC_MODEL         claude-sonnet-4-5
  OC_ADMIN_TOKEN          (required for /invite endpoint)
  OC_ADMIN_TOKEN_FILE     (path to file; takes precedence over env var)
"""

import asyncio
import json
import logging
import os
import re
import secrets
import signal
import sys
import time
from collections import defaultdict
from pathlib import Path
from typing import Any

import aiohttp
from aiohttp import web
from aiohttp_socks import ProxyConnector
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
    load_pem_private_key,
)
from prometheus_client import (
    Counter,
    Gauge,
    Histogram,
    generate_latest,
    CONTENT_TYPE_LATEST,
)
import redis.asyncio as aioredis

# ── Configuration ────────────────────────────────────────────────────────────


def _read_secret(file_env: str, val_env: str, default: str = "") -> str:
    """Read a secret from a file path (file_env) or fall back to an env var."""
    fpath = os.getenv(file_env, "")
    if fpath:
        try:
            return Path(fpath).read_text().strip()
        except OSError as exc:
            log_early = logging.getLogger("oc-agent")
            log_early.warning("Cannot read secret file %s: %s", fpath, exc)
    return os.getenv(val_env, default)


DATA_DIR = Path(os.getenv("OC_DATA_DIR", "/var/lib/oc-tor-net"))
LOG_DIR = Path(os.getenv("OC_LOG_DIR", "/var/log/oc-tor-net"))
HIDDEN_SERVICE_DIR = Path(
    os.getenv("OC_HIDDEN_SERVICE_DIR", "/var/lib/tor/hidden_service")
)
AGENT_PORT = int(os.getenv("OC_AGENT_PORT", "8765"))
METRICS_PORT = int(os.getenv("OC_METRICS_PORT", "9090"))
TOR_PROXY = os.getenv("TOR_SOCKS_PROXY", "socks5h://tor:9050")

# Redis URL: prefer explicit REDIS_URL, otherwise build from password + host
if os.getenv("REDIS_URL"):
    REDIS_URL: str = os.environ["REDIS_URL"]
else:
    _redis_password = _read_secret(
        "REDIS_PASSWORD_FILE", "REDIS_PASSWORD", "changeme-in-production"
    )
    _redis_host = os.getenv("REDIS_HOST", "redis")
    REDIS_URL = f"redis://:{_redis_password}@{_redis_host}:6379/0"

ANTHROPIC_API_KEY = _read_secret("ANTHROPIC_API_KEY_FILE", "ANTHROPIC_API_KEY", "")
ANTHROPIC_MODEL = os.getenv("ANTHROPIC_MODEL", "claude-sonnet-4-5")
ADMIN_TOKEN = _read_secret("OC_ADMIN_TOKEN_FILE", "OC_ADMIN_TOKEN", "")

# Redis key namespaces
REDIS_PEERS_KEY = "oc:peers"
REDIS_NODE_KEY = "oc:node"
REDIS_INVITES_KEY = "oc:invites"
PEER_TTL = 3600  # seconds; peers that miss a heartbeat expire

# Rate limiting
_RATE_LIMIT_REQUESTS = 30  # per IP per window
_RATE_LIMIT_WINDOW = 60.0  # seconds
_rate_window: dict[str, list[float]] = defaultdict(list)

# Heartbeat concurrency cap
_HEARTBEAT_CONCURRENCY = 10

# Maximum accepted request body size
_MAX_BODY_BYTES = 8192

# Valid v3 .onion address pattern (56 base32 chars + ".onion")
_ONION_RE = re.compile(r"^[a-z2-7]{56}\.onion$")

# ── Logging ──────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    stream=sys.stdout,
)
log = logging.getLogger("oc-agent")

# ── Prometheus metrics ───────────────────────────────────────────────────────

PEERS_CONNECTED = Gauge("oc_peers_connected", "Number of active P2P peers")
MESSAGES_SENT = Counter("oc_messages_sent_total", "Total P2P messages sent", ["type"])
MESSAGES_RECV = Counter("oc_messages_received_total", "Total P2P messages received", ["type"])
HEARTBEAT_LATENCY = Histogram(
    "oc_heartbeat_latency_seconds",
    "Round-trip heartbeat latency to peers",
    buckets=[0.1, 0.5, 1.0, 2.0, 5.0, 10.0, 30.0],
)
AI_REQUESTS = Counter("oc_ai_requests_total", "Total Anthropic AI requests")
AI_ERRORS = Counter("oc_ai_errors_total", "Total Anthropic AI request errors")
UPTIME_SECONDS = Gauge("oc_uptime_seconds", "Agent uptime in seconds")

# ── Node identity (Ed25519) ───────────────────────────────────────────────────


def load_or_create_node_identity() -> tuple[str, Ed25519PrivateKey]:
    """
    Load or create a persistent Ed25519 keypair.

    Returns (node_id, private_key) where node_id is the 64-char hex
    encoding of the 32-byte Ed25519 public key.
    """
    key_file = DATA_DIR / "node_key.pem"
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    if key_file.exists():
        pem = key_file.read_bytes()
        private_key: Ed25519PrivateKey = load_pem_private_key(pem, None)  # type: ignore[assignment]
    else:
        private_key = Ed25519PrivateKey.generate()
        pem = private_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
        key_file.write_bytes(pem)
        key_file.chmod(0o600)
        log.info("Created new Ed25519 node identity")

    pub_bytes = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    node_id = pub_bytes.hex()
    log.info("Node identity loaded — node_id=%s", node_id[:16] + "…")
    return node_id, private_key


def load_hidden_service_hostname() -> str:
    """Read the .onion hostname assigned by Tor (may not exist yet at startup)."""
    hostname_file = HIDDEN_SERVICE_DIR / "hostname"
    if hostname_file.exists():
        return hostname_file.read_text().strip()
    return ""


# ── Signature helpers ─────────────────────────────────────────────────────────


def _canonical_payload(peer: dict) -> bytes:
    """Return a stable, signed byte string for the peer announcement fields."""
    return json.dumps(
        {k: peer[k] for k in ("node_id", "onion", "port", "timestamp")},
        sort_keys=True,
        separators=(",", ":"),
    ).encode()


def sign_announcement(private_key: Ed25519PrivateKey, peer: dict) -> str:
    """Sign a peer announcement; returns hex-encoded 64-byte signature."""
    return private_key.sign(_canonical_payload(peer)).hex()


def verify_announcement(peer: dict) -> bool:
    """
    Verify the Ed25519 signature on an incoming peer announcement.
    Returns True only if the signature is valid.
    """
    try:
        node_id_hex = peer["node_id"]
        sig_hex = peer["signature"]
        pub_key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(node_id_hex))
        pub_key.verify(bytes.fromhex(sig_hex), _canonical_payload(peer))
        return True
    except (InvalidSignature, KeyError, ValueError):
        return False


# ── Peer validation ───────────────────────────────────────────────────────────


def _validate_peer(peer: Any) -> str | None:
    """
    Validate a peer announcement dict.
    Returns an error message string, or None if the record is valid.
    """
    if not isinstance(peer, dict):
        return "body must be a JSON object"

    node_id = peer.get("node_id", "")
    if not isinstance(node_id, str) or len(node_id) != 64:
        return "node_id must be a 64-char hex string (Ed25519 public key)"
    if not all(c in "0123456789abcdef" for c in node_id):
        return "node_id must be lowercase hex"

    onion = peer.get("onion", "")
    if not isinstance(onion, str) or not _ONION_RE.match(onion):
        return "onion must be a valid v3 .onion address"

    port = peer.get("port", AGENT_PORT)
    if not isinstance(port, int) or not (1 <= port <= 65535):
        return "port must be an integer in range 1–65535"

    ts = peer.get("timestamp", 0)
    if not isinstance(ts, (int, float)):
        return "timestamp must be a number"
    skew = abs(time.time() - float(ts))
    if skew > 300:
        return f"timestamp skew too large ({skew:.0f}s); check clocks"

    if "signature" not in peer or not isinstance(peer["signature"], str):
        return "signature field required"
    if len(peer["signature"]) != 128 or not all(
        c in "0123456789abcdef" for c in peer["signature"]
    ):
        return "signature must be a 128-char hex string"

    return None


async def _read_bounded_json(request: web.Request) -> tuple[Any, web.Response | None]:
    """
    Read and parse the request body, enforcing a size cap.
    Returns (parsed_json, None) on success or (None, error_response) on failure.
    """
    cl = request.content_length
    if cl is not None and cl > _MAX_BODY_BYTES:
        return None, web.json_response({"error": "request body too large"}, status=413)
    raw = await request.read()
    if len(raw) > _MAX_BODY_BYTES:
        return None, web.json_response({"error": "request body too large"}, status=413)
    try:
        return json.loads(raw), None
    except json.JSONDecodeError:
        return None, web.json_response({"error": "invalid JSON"}, status=400)


# ── Redis helpers ─────────────────────────────────────────────────────────────


async def redis_connect() -> aioredis.Redis:
    """Return an authenticated Redis connection."""
    return await aioredis.from_url(REDIS_URL, decode_responses=True)


async def register_self(redis: aioredis.Redis, node_id: str, onion: str) -> None:
    """Publish this node's record into the Hub state bus."""
    record = {
        "node_id": node_id,
        "onion": onion,
        "port": AGENT_PORT,
        "seen": time.time(),
    }
    await redis.hset(REDIS_NODE_KEY, node_id, json.dumps(record))
    await redis.expire(REDIS_NODE_KEY, PEER_TTL * 2)


async def get_peers(redis: aioredis.Redis) -> list[dict]:
    """Return all peers from the Hub state bus."""
    raw = await redis.hgetall(REDIS_PEERS_KEY)
    peers = []
    for v in raw.values():
        try:
            peers.append(json.loads(v))
        except json.JSONDecodeError:
            pass
    return peers


async def upsert_peer(redis: aioredis.Redis, peer: dict) -> None:
    """Insert or refresh a peer record."""
    peer["seen"] = time.time()
    await redis.hset(REDIS_PEERS_KEY, peer["node_id"], json.dumps(peer))
    await redis.expire(REDIS_PEERS_KEY, PEER_TTL * 2)


async def remove_stale_peers(redis: aioredis.Redis) -> int:
    """Delete peers whose last-seen timestamp is older than PEER_TTL."""
    peers = await redis.hgetall(REDIS_PEERS_KEY)
    now = time.time()
    removed = 0
    for k, v in peers.items():
        try:
            p = json.loads(v)
            if now - p.get("seen", 0) > PEER_TTL:
                await redis.hdel(REDIS_PEERS_KEY, k)
                removed += 1
        except json.JSONDecodeError:
            await redis.hdel(REDIS_PEERS_KEY, k)
            removed += 1
    return removed


# ── Tor SOCKS5 outbound ───────────────────────────────────────────────────────


def tor_connector() -> ProxyConnector:
    """Create an aiohttp connector that routes through Tor SOCKS5."""
    return ProxyConnector.from_url(TOR_PROXY)


async def ping_peer(peer: dict) -> float | None:
    """
    Send a /ping request to a peer via the Tor SOCKS5 proxy.
    Returns round-trip latency in seconds or None on failure.
    """
    onion = peer.get("onion", "")
    port = peer.get("port", AGENT_PORT)
    if not onion:
        return None
    url = f"http://{onion}:{port}/ping"
    t0 = time.monotonic()
    try:
        connector = tor_connector()
        async with aiohttp.ClientSession(connector=connector) as session:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=30)) as resp:
                if resp.status == 200:
                    latency = time.monotonic() - t0
                    HEARTBEAT_LATENCY.observe(latency)
                    return latency
    except Exception as exc:
        log.debug("Ping to %s failed: %s", onion, exc)
    return None


# ── AI integration ────────────────────────────────────────────────────────────


async def ask_claude(prompt: str) -> str:
    """Send a prompt to Anthropic Claude via Tor SOCKS5 and return the response text."""
    if not ANTHROPIC_API_KEY:
        return "AI integration disabled (ANTHROPIC_API_KEY not set)."
    AI_REQUESTS.inc()
    headers = {
        "x-api-key": ANTHROPIC_API_KEY,
        "anthropic-version": "2023-06-01",
        "content-type": "application/json",
    }
    body = {
        "model": ANTHROPIC_MODEL,
        "max_tokens": 1024,
        "messages": [{"role": "user", "content": prompt}],
    }
    try:
        async with aiohttp.ClientSession(connector=tor_connector()) as session:
            async with session.post(
                "https://api.anthropic.com/v1/messages",
                headers=headers,
                json=body,
                timeout=aiohttp.ClientTimeout(total=60),
            ) as resp:
                resp.raise_for_status()
                data = await resp.json()
                return data["content"][0]["text"]
    except Exception as exc:
        AI_ERRORS.inc()
        log.error("Anthropic request failed: %s", exc)
        return f"AI request error: {exc}"


# ── Rate limiting middleware ───────────────────────────────────────────────────


@web.middleware
async def rate_limit_middleware(
    request: web.Request, handler: Any
) -> web.StreamResponse:
    """Sliding-window per-IP rate limiter (_RATE_LIMIT_REQUESTS / minute)."""
    ip = request.remote or "unknown"
    now = time.monotonic()
    window = _rate_window[ip]
    cutoff = now - _RATE_LIMIT_WINDOW
    while window and window[0] < cutoff:
        window.pop(0)
    if len(window) >= _RATE_LIMIT_REQUESTS:
        return web.Response(status=429, text="rate limit exceeded\n")
    window.append(now)
    return await handler(request)


# ── HTTP handlers (P2P + metrics) ─────────────────────────────────────────────


async def handle_ping(request: web.Request) -> web.Response:
    """Health/liveness ping for peer heartbeats."""
    return web.json_response({"status": "ok", "ts": time.time()})


async def handle_announce(request: web.Request) -> web.Response:
    """
    Peer announces itself: POST /announce
    Body: {node_id, onion, port, timestamp, signature}
    Validates and verifies the Ed25519 signature before storing.
    """
    peer, err = await _read_bounded_json(request)
    if err:
        return err
    error_msg = _validate_peer(peer)
    if error_msg:
        return web.json_response({"error": error_msg}, status=400)
    if not verify_announcement(peer):
        return web.json_response({"error": "invalid signature"}, status=403)
    redis: aioredis.Redis = request.app["redis"]
    await upsert_peer(redis, peer)
    MESSAGES_RECV.labels(type="announce").inc()
    log.info("Peer announced: %s @ %s", peer["node_id"][:16], peer["onion"])
    return web.json_response({"status": "ok"})


async def handle_peers(request: web.Request) -> web.Response:
    """Return the current peer list from the Hub state bus."""
    redis: aioredis.Redis = request.app["redis"]
    peers = await get_peers(redis)
    PEERS_CONNECTED.set(len(peers))
    return web.json_response({"peers": peers, "count": len(peers)})


async def handle_ai(request: web.Request) -> web.Response:
    """
    POST /ai  body: {prompt: "..."}
    Forward to Anthropic Claude and return the answer.
    """
    body, err = await _read_bounded_json(request)
    if err:
        return err
    prompt = body.get("prompt", "").strip() if isinstance(body, dict) else ""
    if not prompt:
        return web.json_response({"error": "prompt required"}, status=400)
    answer = await ask_claude(prompt)
    return web.json_response({"answer": answer})


async def handle_metrics(_request: web.Request) -> web.Response:
    """Prometheus /metrics endpoint."""
    return web.Response(
        body=generate_latest(),
        headers={"Content-Type": CONTENT_TYPE_LATEST},
    )


def _check_admin(request: web.Request) -> bool:
    """Return True if the request carries a valid admin bearer token."""
    if not ADMIN_TOKEN:
        return False
    auth = request.headers.get("Authorization", "")
    expected = "Bearer " + ADMIN_TOKEN
    return secrets.compare_digest(auth.encode(), expected.encode())


async def handle_invite_create(request: web.Request) -> web.Response:
    """POST /invite  — generate a one-time swarm invite code (admin only)."""
    if not _check_admin(request):
        return web.json_response({"error": "unauthorized"}, status=401)
    code = secrets.token_urlsafe(24)
    redis: aioredis.Redis = request.app["redis"]
    await redis.setex(f"{REDIS_INVITES_KEY}:{code}", 86400, request.app["node_id"])
    return web.json_response({"invite": code})


async def handle_invite_accept(request: web.Request) -> web.Response:
    """
    POST /connect  body: {invite: "CODE"}
    Validate invite code, register caller as peer.
    """
    body, err = await _read_bounded_json(request)
    if err:
        return err
    if not isinstance(body, dict):
        return web.json_response({"error": "body must be a JSON object"}, status=400)
    code = body.get("invite", "").strip()
    if not code:
        return web.json_response({"error": "invite required"}, status=400)
    redis: aioredis.Redis = request.app["redis"]
    issuer = await redis.get(f"{REDIS_INVITES_KEY}:{code}")
    if not issuer:
        return web.json_response({"error": "invalid or expired invite"}, status=403)
    await redis.delete(f"{REDIS_INVITES_KEY}:{code}")
    log.info("Invite %s accepted", code[:8])
    return web.json_response({"status": "enrolled", "issued_by": issuer})


# ── Background tasks ──────────────────────────────────────────────────────────


async def heartbeat_task(app: web.Application) -> None:
    """Periodically ping all known peers and prune stale ones (bounded concurrency)."""
    sem = asyncio.Semaphore(_HEARTBEAT_CONCURRENCY)

    async def _ping_bounded(peer: dict) -> float | None:
        async with sem:
            return await ping_peer(peer)

    while True:
        await asyncio.sleep(60)
        redis: aioredis.Redis = app["redis"]
        peers = await get_peers(redis)
        if peers:
            tasks = [asyncio.create_task(_ping_bounded(p)) for p in peers]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            active = sum(
                1 for r in results if isinstance(r, float) and r is not None
            )
            PEERS_CONNECTED.set(active)
            log.debug(
                "Heartbeat: %d/%d peers reachable", active, len(peers)
            )
        pruned = await remove_stale_peers(redis)
        if pruned:
            log.info("Pruned %d stale peer(s)", pruned)
        MESSAGES_SENT.labels(type="heartbeat").inc()


async def uptime_task(_app: web.Application) -> None:
    """Update the uptime gauge every second."""
    start = time.monotonic()
    while True:
        UPTIME_SECONDS.set(time.monotonic() - start)
        await asyncio.sleep(1)


async def on_startup(app: web.Application) -> None:
    """Initialise Redis, node identity, and background tasks on startup."""
    redis = await redis_connect()
    app["redis"] = redis

    node_id, private_key = load_or_create_node_identity()
    app["node_id"] = node_id
    app["private_key"] = private_key
    onion = load_hidden_service_hostname()
    app["onion"] = onion

    await register_self(redis, node_id, onion)

    log.info("Agent starting — node_id=%s onion=%s", node_id[:16] + "…", onion or "<pending>")

    app["heartbeat"] = asyncio.ensure_future(heartbeat_task(app))
    app["uptime"] = asyncio.ensure_future(uptime_task(app))


async def on_cleanup(app: web.Application) -> None:
    """Gracefully cancel background tasks and close Redis."""
    for task_key in ("heartbeat", "uptime"):
        task = app.get(task_key)
        if task:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
    redis: aioredis.Redis | None = app.get("redis")
    if redis:
        await redis.aclose()


# ── App factory ───────────────────────────────────────────────────────────────


def build_app() -> tuple[web.Application, web.Application]:
    """
    Build and return two aiohttp apps:
      - p2p_app  — listens on AGENT_PORT  (P2P protocol)
      - metrics_app — listens on METRICS_PORT (Prometheus scrape)
    """
    p2p_app = web.Application(middlewares=[rate_limit_middleware])
    p2p_app.router.add_get("/ping", handle_ping)
    p2p_app.router.add_post("/announce", handle_announce)
    p2p_app.router.add_get("/peers", handle_peers)
    p2p_app.router.add_post("/ai", handle_ai)
    p2p_app.router.add_post("/invite", handle_invite_create)
    p2p_app.router.add_post("/connect", handle_invite_accept)
    p2p_app.on_startup.append(on_startup)
    p2p_app.on_cleanup.append(on_cleanup)

    metrics_app = web.Application()
    metrics_app.router.add_get("/metrics", handle_metrics)
    metrics_app.router.add_get("/healthz", handle_ping)

    return p2p_app, metrics_app


# ── Entry point ───────────────────────────────────────────────────────────────


async def main() -> None:
    p2p_app, metrics_app = build_app()

    p2p_runner = web.AppRunner(p2p_app)
    await p2p_runner.setup()
    p2p_site = web.TCPSite(p2p_runner, "0.0.0.0", AGENT_PORT)

    metrics_runner = web.AppRunner(metrics_app)
    await metrics_runner.setup()
    metrics_site = web.TCPSite(metrics_runner, "0.0.0.0", METRICS_PORT)

    await p2p_site.start()
    await metrics_site.start()

    log.info("P2P agent listening on port %d", AGENT_PORT)
    log.info("Metrics server listening on port %d", METRICS_PORT)

    # Block until SIGINT / SIGTERM
    loop = asyncio.get_running_loop()
    stop = loop.create_future()

    def _stop(*_: Any) -> None:
        if not stop.done():
            stop.set_result(None)

    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, _stop)

    await stop
    log.info("Shutting down…")
    await p2p_runner.cleanup()
    await metrics_runner.cleanup()


if __name__ == "__main__":
    asyncio.run(main())
