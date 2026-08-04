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
  OC_DATA_DIR        /var/lib/oc-tor-net
  OC_LOG_DIR         /var/log/oc-tor-net
  OC_AGENT_PORT      8765
  OC_METRICS_PORT    9090
  TOR_SOCKS_PROXY    socks5h://tor:9050
  REDIS_URL          redis://:changeme-in-production@redis:6379/0
  ANTHROPIC_API_KEY  (optional — AI features disabled when absent)
"""

import asyncio
import json
import logging
import os
import secrets
import signal
import sys
import time
import uuid
from pathlib import Path
from typing import Any

import aiohttp
from aiohttp import web
from aiohttp_socks import ProxyConnector
from prometheus_client import (
    Counter,
    Gauge,
    Histogram,
    generate_latest,
    CONTENT_TYPE_LATEST,
)
import redis.asyncio as aioredis

# ── Configuration ────────────────────────────────────────────────────────────

DATA_DIR = Path(os.getenv("OC_DATA_DIR", "/var/lib/oc-tor-net"))
LOG_DIR = Path(os.getenv("OC_LOG_DIR", "/var/log/oc-tor-net"))
AGENT_PORT = int(os.getenv("OC_AGENT_PORT", "8765"))
METRICS_PORT = int(os.getenv("OC_METRICS_PORT", "9090"))
TOR_PROXY = os.getenv("TOR_SOCKS_PROXY", "socks5h://tor:9050")
REDIS_URL = os.getenv("REDIS_URL", "redis://:changeme-in-production@redis:6379/0")
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")

# Redis key namespaces
REDIS_PEERS_KEY = "oc:peers"
REDIS_NODE_KEY = "oc:node"
REDIS_INVITES_KEY = "oc:invites"
PEER_TTL = 3600  # seconds; peers that miss a heartbeat expire

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

# ── Node identity ─────────────────────────────────────────────────────────────


def load_or_create_node_id() -> str:
    """Load persistent node ID from disk or generate a new one."""
    id_file = DATA_DIR / "node_id"
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    if id_file.exists():
        return id_file.read_text().strip()
    node_id = str(uuid.uuid4())
    id_file.write_text(node_id)
    log.info("Created new node ID: %s", node_id)
    return node_id


def load_hidden_service_hostname() -> str:
    """Read the .onion hostname assigned by Tor (may not exist yet at startup)."""
    hostname_file = DATA_DIR / "hidden_service" / "hostname"
    if hostname_file.exists():
        return hostname_file.read_text().strip()
    return ""


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
    """Send a prompt to Anthropic Claude and return the response text."""
    if not ANTHROPIC_API_KEY:
        return "AI integration disabled (ANTHROPIC_API_KEY not set)."
    AI_REQUESTS.inc()
    headers = {
        "x-api-key": ANTHROPIC_API_KEY,
        "anthropic-version": "2023-06-01",
        "content-type": "application/json",
    }
    body = {
        "model": "claude-3-5-sonnet-20241022",
        "max_tokens": 1024,
        "messages": [{"role": "user", "content": prompt}],
    }
    try:
        connector = tor_connector()
        async with aiohttp.ClientSession(connector=connector) as session:
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


# ── HTTP handlers (P2P + metrics) ─────────────────────────────────────────────


async def handle_ping(request: web.Request) -> web.Response:
    """Health/liveness ping for peer heartbeats."""
    return web.json_response({"status": "ok", "ts": time.time()})


async def handle_announce(request: web.Request) -> web.Response:
    """
    Peer announces itself: POST /announce  body: {node_id, onion, port}
    Stores the peer in Redis Hub state bus.
    """
    try:
        peer = await request.json()
        if not all(k in peer for k in ("node_id", "onion")):
            return web.json_response({"error": "missing fields"}, status=400)
        redis: aioredis.Redis = request.app["redis"]
        await upsert_peer(redis, peer)
        MESSAGES_RECV.labels(type="announce").inc()
        log.info("Peer announced: %s @ %s", peer["node_id"][:8], peer["onion"])
        return web.json_response({"status": "ok"})
    except Exception as exc:
        log.error("announce error: %s", exc)
        return web.json_response({"error": str(exc)}, status=500)


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
    try:
        body = await request.json()
        prompt = body.get("prompt", "").strip()
        if not prompt:
            return web.json_response({"error": "prompt required"}, status=400)
        answer = await ask_claude(prompt)
        return web.json_response({"answer": answer})
    except Exception as exc:
        return web.json_response({"error": str(exc)}, status=500)


async def handle_metrics(_request: web.Request) -> web.Response:
    """Prometheus /metrics endpoint."""
    return web.Response(
        body=generate_latest(),
        content_type=CONTENT_TYPE_LATEST,
    )


async def handle_invite_create(request: web.Request) -> web.Response:
    """POST /invite  — generate a one-time swarm invite code."""
    code = secrets.token_urlsafe(24)
    redis: aioredis.Redis = request.app["redis"]
    await redis.setex(f"{REDIS_INVITES_KEY}:{code}", 86400, request.app["node_id"])
    return web.json_response({"invite": code})


async def handle_invite_accept(request: web.Request) -> web.Response:
    """
    POST /connect  body: {invite: "CODE"}
    Validate invite code, register caller as peer.
    """
    try:
        body = await request.json()
        code = body.get("invite", "").strip()
        if not code:
            return web.json_response({"error": "invite required"}, status=400)
        redis: aioredis.Redis = request.app["redis"]
        issuer = await redis.get(f"{REDIS_INVITES_KEY}:{code}")
        if not issuer:
            return web.json_response({"error": "invalid or expired invite"}, status=403)
        await redis.delete(f"{REDIS_INVITES_KEY}:{code}")
        # Register the caller as a peer if they provided their peer record
        caller = {k: v for k, v in body.items() if k != "invite"}
        if caller.get("node_id") and caller.get("onion"):
            await upsert_peer(redis, caller)
            log.info("Peer enrolled via invite: %s @ %s", caller["node_id"][:8], caller["onion"])
        log.info("Invite %s accepted", code[:8])
        return web.json_response({"status": "enrolled", "issued_by": issuer})
    except Exception as exc:
        return web.json_response({"error": str(exc)}, status=500)


# ── Background tasks ──────────────────────────────────────────────────────────


async def heartbeat_task(app: web.Application) -> None:
    """Periodically ping all known peers and prune stale ones."""
    while True:
        await asyncio.sleep(60)
        redis: aioredis.Redis = app["redis"]
        peers = await get_peers(redis)
        active = 0
        for peer in peers:
            latency = await ping_peer(peer)
            if latency is not None:
                active += 1
                log.debug("Peer %s latency=%.2fs", peer["node_id"][:8], latency)
            else:
                log.debug("Peer %s unreachable", peer["node_id"][:8])
        PEERS_CONNECTED.set(active)
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
    """Initialise Redis and background tasks on application startup."""
    redis = await redis_connect()
    app["redis"] = redis

    node_id = load_or_create_node_id()
    app["node_id"] = node_id
    onion = load_hidden_service_hostname()
    app["onion"] = onion

    await register_self(redis, node_id, onion)

    log.info("Agent starting — node_id=%s onion=%s", node_id, onion or "<pending>")

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
    p2p_app = web.Application()
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
