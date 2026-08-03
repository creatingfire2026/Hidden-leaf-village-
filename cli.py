"""
OpenClaw Tor P2P Node — CLI client
Symmetry Labs Infrastructure

Usage (inside the agent container):
  python3 /app/cli.py peers
  python3 /app/cli.py ping
  python3 /app/cli.py invite
  python3 /app/cli.py connect 'INVITE_CODE'
  python3 /app/cli.py ask 'How many peers are active?'
"""

import argparse
import json
import sys
import urllib.request
import urllib.error

BASE_URL = "http://localhost:8765"


def _get(path: str) -> dict:
    with urllib.request.urlopen(f"{BASE_URL}{path}", timeout=10) as resp:
        return json.loads(resp.read())


def _post(path: str, payload: dict) -> dict:
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        f"{BASE_URL}{path}",
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=15) as resp:
        return json.loads(resp.read())


def cmd_peers(_args: argparse.Namespace) -> None:
    result = _get("/peers")
    peers = result.get("peers", [])
    if not peers:
        print("No peers known.")
        return
    print(f"{'NODE ID':36}  {'ONION':56}  {'PORT':6}  {'SEEN (s ago)':12}")
    print("-" * 120)
    import time
    now = time.time()
    for p in peers:
        age = int(now - p.get("seen", now))
        print(f"{p.get('node_id','?'):36}  {p.get('onion','?'):56}  {p.get('port',0):6}  {age:12}")


def cmd_ping(_args: argparse.Namespace) -> None:
    result = _get("/ping")
    print(json.dumps(result, indent=2))


def cmd_invite(_args: argparse.Namespace) -> None:
    result = _post("/invite", {})
    print("Invite code:", result.get("invite"))


def cmd_connect(args: argparse.Namespace) -> None:
    result = _post("/connect", {"invite": args.code})
    print(json.dumps(result, indent=2))


def cmd_ask(args: argparse.Namespace) -> None:
    result = _post("/ai", {"prompt": args.prompt})
    print(result.get("answer", result))


def main() -> None:
    parser = argparse.ArgumentParser(
        description="OpenClaw P2P Tor Node — CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="command")

    sub.add_parser("peers", help="List known peers")
    sub.add_parser("ping", help="Ping the local agent")
    sub.add_parser("invite", help="Generate a swarm invite code")

    p_connect = sub.add_parser("connect", help="Enroll using an invite code")
    p_connect.add_argument("code", help="Invite code")

    p_ask = sub.add_parser("ask", help="Ask the AI assistant a question")
    p_ask.add_argument("prompt", help="Prompt text")

    args = parser.parse_args()

    handlers = {
        "peers": cmd_peers,
        "ping": cmd_ping,
        "invite": cmd_invite,
        "connect": cmd_connect,
        "ask": cmd_ask,
    }

    if args.command not in handlers:
        parser.print_help()
        sys.exit(1)

    try:
        handlers[args.command](args)
    except urllib.error.URLError as exc:
        print(f"Connection error: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
