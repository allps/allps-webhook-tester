# webhook-tester

Tiny FastAPI app for inspecting outbound webhook deliveries. Files only, no DB.

- Receives on `POST /webhook-test` (always returns 200, even on bad signature)
- Verifies HMAC-SHA256 over `{timestamp}.{body}` against any configured secret
- Persists every delivery (verified **or** failed) as JSON on disk
- Web UI polls for new deliveries, shows payload, allows download/delete

## Layout

```
app.py                # backend
static/index.html     # UI
data/secrets.json     # signing secrets
data/deliveries/*.json
```

## Run

```bash
uv run --with fastapi --with 'uvicorn[standard]' --with loguru \
  app.py --host 0.0.0.0 --port 8000 --user admin --password s3cret
```

Or with a proper project:

```bash
uv init --bare
uv add fastapi 'uvicorn[standard]' loguru
uv run app.py --user admin --password s3cret
```

## Flags

| flag | default | notes |
|---|---|---|
| `--host` | `0.0.0.0` | |
| `--port` | `8000` | |
| `--user` / `--password` | `admin` / `admin` | HTTP Basic on `/` and `/api/*` |
| `--data-dir` | `./data` | where `secrets.json` + `deliveries/` live |
| `--max-skew` | `300` | replay window in seconds; `0` disables |

Env equivalents: `WEBHOOK_TESTER_USER`, `WEBHOOK_TESTER_PASSWORD`, `WEBHOOK_TESTER_DATA`.

## Point your sender at

```
POST http://<host>:8000/webhook-test
Headers: x-webhook-signature, x-webhook-timestamp
```

`/webhook-test` is intentionally unauthenticated — the signature is the auth.

## Endpoints

- `GET  /` — UI (basic auth)
- `GET  /health`
- `POST /webhook-test`
- `GET/POST/DELETE /api/secrets`
- `GET/DELETE /api/deliveries`
- `GET /api/deliveries/{id}` · `GET …/download` · `DELETE …/{id}`

## Reset

`rm -rf data/` — that's the whole state.
