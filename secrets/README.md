# Secrets — OpenClaw Tor P2P Node

Docker Compose reads secrets from plain-text files in this directory.
The `.gitignore` prevents them from being committed.

## Setup

```bash
mkdir -p secrets

# Redis password — used by the redis service and the agent
printf 'your-strong-redis-password' > secrets/redis_password.txt

# Grafana admin password
printf 'your-strong-grafana-password' > secrets/grafana_password.txt

# Anthropic Claude API key (leave empty to disable AI features)
printf '' > secrets/anthropic_api_key.txt

# Admin bearer token for the /invite endpoint
printf 'your-strong-admin-token' > secrets/admin_token.txt

# Lock down permissions
chmod 600 secrets/*.txt
```

## Usage

To create a swarm invite code, supply the admin token in the
`Authorization` header:

```bash
# Read the token, then call the API
TOKEN=$(< secrets/admin_token.txt)
curl -sf -X POST http://localhost:8765/invite \
     -H "Authorization: ******"
```

## Notes

- All `*.txt` files in this directory are git-ignored.
- Do **not** store secrets in `.env` files or environment variables in
  production; use the files above so that the values are never
  visible in process listings or container inspect output.
