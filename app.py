#!/usr/bin/env python3
"""Dead-simple outbound webhook delivery tester.

- Receives deliveries on POST /webhook-test
- Verifies HMAC-SHA256 signatures against any configured secret
- Stores EVERY delivery on disk as JSON (verified OR failed)
- Serves a small HTML UI: polling, secret management, payload download
- No database. Files only.
"""

from __future__ import annotations

import argparse
import hmac
import json
import os
import secrets as pysecrets
import threading
import time
import uuid
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from typing import Any

import uvicorn
from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import HTMLResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from loguru import logger


def _load_dotenv(path: str = "/app/.env") -> None:
    p = Path(path)
    if not p.is_file():
        return
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition("=")
        os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


_load_dotenv()

# ---------------------------------------------------------------------------
# Config / constants
# ---------------------------------------------------------------------------

SIGNATURE_HEADER = "x-webhook-signature"
TIMESTAMP_HEADER = "x-webhook-timestamp"

BASE_DIR = Path(__file__).resolve().parent
INDEX_FILE = BASE_DIR / "static" / "index.html"

DATA_DIR = Path(os.environ.get("WEBHOOK_TESTER_DATA", "/data")).resolve()
SECRETS_FILE = DATA_DIR / "secrets.json"
DELIVERIES_DIR = DATA_DIR / "deliveries"

AUTH_USER = os.environ.get("WEBHOOK_TESTER_USER", "admin")
AUTH_PASSWORD = os.environ.get("WEBHOOK_TESTER_PASSWORD", "admin")
MAX_SKEW_SECONDS: int | None = 5 * 60  # None disables the replay window check

_lock = threading.RLock()
security = HTTPBasic()


def _ensure_dirs() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    DELIVERIES_DIR.mkdir(parents=True, exist_ok=True)
    if not SECRETS_FILE.exists():
        SECRETS_FILE.write_text("[]", encoding="utf-8")


_ensure_dirs()


# ---------------------------------------------------------------------------
# File storage (no database anywhere)
# ---------------------------------------------------------------------------


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def load_secrets() -> list[dict[str, Any]]:
    with _lock:
        try:
            return json.loads(SECRETS_FILE.read_text(encoding="utf-8"))
        except (FileNotFoundError, json.JSONDecodeError):
            return []


def save_secrets(items: list[dict[str, Any]]) -> None:
    with _lock:
        tmp = SECRETS_FILE.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(items, indent=2), encoding="utf-8")
        tmp.replace(SECRETS_FILE)


def save_delivery(delivery: dict[str, Any]) -> None:
    path = DELIVERIES_DIR / f"{delivery['id']}.json"
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(delivery, indent=2), encoding="utf-8")
    tmp.replace(path)


def load_delivery(delivery_id: str) -> dict[str, Any] | None:
    if not delivery_id or not delivery_id.isalnum():
        return None
    path = DELIVERIES_DIR / f"{delivery_id}.json"
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None


def list_delivery_files(limit: int) -> list[Path]:
    if not DELIVERIES_DIR.exists():
        return []
    files = [p for p in DELIVERIES_DIR.glob("*.json")]
    files.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    return files[:limit]


def delivery_summary(d: dict[str, Any]) -> dict[str, Any]:
    body = d.get("body") or {}
    interview = body.get("interview") if isinstance(body, dict) else {}
    interview = interview or {}
    headers = d.get("headers") or {}
    return {
        "id": d.get("id"),
        "received_at": d.get("received_at"),
        "verified": bool(d.get("verified")),
        "verification_error": d.get("verification_error"),
        "matched_secret": d.get("matched_secret"),
        "event": d.get("event") or headers.get("x-webhook-event"),
        "interview_id": interview.get("id"),
        "interview_kind": interview.get("kind"),
    }


# ---------------------------------------------------------------------------
# HMAC verification
# ---------------------------------------------------------------------------


class WebhookVerificationError(Exception):
    pass


def verify_webhook_signature(
    secret: str,
    raw_body: bytes,
    headers: Any,
    *,
    max_skew_seconds: int | None,
) -> None:
    """HMAC-SHA256 over b'{timestamp}.{body}'."""
    signature = headers.get(SIGNATURE_HEADER)
    timestamp = headers.get(TIMESTAMP_HEADER)

    if not signature:
        raise WebhookVerificationError(f"Missing {SIGNATURE_HEADER} header")
    if not timestamp:
        raise WebhookVerificationError(f"Missing {TIMESTAMP_HEADER} header")

    if max_skew_seconds is not None:
        try:
            age = abs(int(time.time()) - int(timestamp))
        except (TypeError, ValueError):
            raise WebhookVerificationError(f"Invalid {TIMESTAMP_HEADER}: {timestamp!r}")
        if age > max_skew_seconds:
            raise WebhookVerificationError(
                f"Timestamp too old ({age}s > {max_skew_seconds}s)"
            )

    signed = timestamp.encode("utf-8") + b"." + raw_body
    expected = "sha256=" + hmac.new(secret.encode("utf-8"), signed, sha256).hexdigest()
    if not hmac.compare_digest(expected, signature):
        raise WebhookVerificationError("Signature mismatch")


def verify_against_all(
    raw_body: bytes, headers: Any
) -> tuple[bool, str | None, str | None]:
    """Return (verified, matched_secret_name, error_message)."""
    configured = load_secrets()
    if not configured:
        return False, None, "No signing secrets configured"

    last_error = "Signature mismatch"
    for entry in configured:
        try:
            verify_webhook_signature(
                entry["value"], raw_body, headers, max_skew_seconds=MAX_SKEW_SECONDS
            )
            return True, entry["name"], None
        except WebhookVerificationError as exc:
            last_error = str(exc)
        except Exception as exc:  # pragma: no cover
            last_error = f"Unexpected error: {exc}"
    return False, None, last_error


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------


def require_auth(creds: HTTPBasicCredentials = Depends(security)) -> str:
    user_ok = pysecrets.compare_digest(creds.username, AUTH_USER)
    pass_ok = pysecrets.compare_digest(creds.password, AUTH_PASSWORD)
    if not (user_ok and pass_ok):
        raise HTTPException(
            status_code=401,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Basic"},
        )
    return creds.username


# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------

app = FastAPI(title="Webhook Delivery Tester")


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/webhook-test")
async def receive_webhook(req: Request) -> dict[str, Any]:
    raw_body = await req.body()
    try:
        parsed = json.loads(raw_body)
    except Exception:
        parsed = None

    verified, matched, error = verify_against_all(raw_body, req.headers)

    delivery = {
        "id": uuid.uuid4().hex,
        "received_at": _now_iso(),
        "client": req.client.host if req.client else None,
        "event": req.headers.get("x-webhook-event"),
        "headers": dict(req.headers),
        "body": parsed,
        "raw_body": raw_body.decode("utf-8", errors="replace"),
        "verified": verified,
        "matched_secret": matched,
        "verification_error": None if verified else error,
    }
    save_delivery(delivery)

    if verified:
        logger.info(f"Delivery {delivery['id']} verified with secret '{matched}'")
    else:
        logger.warning(f"Delivery {delivery['id']} FAILED verification: {error}")

    # Always 200 so the sender doesn't retry while you're debugging.
    return {"status": "ok", "verified": verified, "delivery_id": delivery["id"]}


# ---- UI ------------------------------------------------------------------


@app.get("/", response_class=HTMLResponse)
def index(_: str = Depends(require_auth)) -> HTMLResponse:
    return HTMLResponse(INDEX_FILE.read_text(encoding="utf-8"))


# ---- Secrets API ---------------------------------------------------------


@app.get("/api/secrets")
def api_list_secrets(_: str = Depends(require_auth)) -> list[dict[str, Any]]:
    return [
        {
            "id": s["id"],
            "name": s["name"],
            "value": s["value"],
            "created_at": s.get("created_at"),
        }
        for s in load_secrets()
    ]


@app.post("/api/secrets", status_code=201)
def api_add_secret(
    payload: dict[str, Any], _: str = Depends(require_auth)
) -> dict[str, Any]:
    name = (payload.get("name") or "").strip()
    value = (payload.get("value") or "").strip()
    if not name or not value:
        raise HTTPException(400, "'name' and 'value' are both required")

    items = load_secrets()
    entry = {
        "id": uuid.uuid4().hex,
        "name": name,
        "value": value,
        "created_at": _now_iso(),
    }
    items.append(entry)
    save_secrets(items)
    return {
        "id": entry["id"],
        "name": name,
        "value": value,
        "created_at": entry["created_at"],
    }


@app.delete("/api/secrets/{secret_id}", status_code=204)
def api_delete_secret(secret_id: str, _: str = Depends(require_auth)) -> Response:
    items = load_secrets()
    kept = [s for s in items if s["id"] != secret_id]
    if len(kept) == len(items):
        raise HTTPException(404, "Secret not found")
    save_secrets(kept)
    return Response(status_code=204)


# ---- Deliveries API ------------------------------------------------------


@app.get("/api/deliveries")
def api_list_deliveries(
    limit: int = 100, _: str = Depends(require_auth)
) -> list[dict[str, Any]]:
    limit = max(1, min(limit, 500))
    out: list[dict[str, Any]] = []
    for path in list_delivery_files(limit):
        try:
            out.append(delivery_summary(json.loads(path.read_text(encoding="utf-8"))))
        except Exception:
            continue
    return out


@app.get("/api/deliveries/{delivery_id}")
def api_get_delivery(
    delivery_id: str, _: str = Depends(require_auth)
) -> dict[str, Any]:
    d = load_delivery(delivery_id)
    if d is None:
        raise HTTPException(404, "Delivery not found")
    return d


@app.get("/api/deliveries/{delivery_id}/download")
def api_download_delivery(delivery_id: str, _: str = Depends(require_auth)) -> Response:
    d = load_delivery(delivery_id)
    if d is None:
        raise HTTPException(404, "Delivery not found")
    raw = d.get("raw_body") or ""
    return Response(
        content=raw,
        media_type="application/json",
        headers={
            "Content-Disposition": f'attachment; filename="delivery_{delivery_id}.json"'
        },
    )


@app.delete("/api/deliveries/{delivery_id}", status_code=204)
def api_delete_delivery(delivery_id: str, _: str = Depends(require_auth)) -> Response:
    if not delivery_id.isalnum():
        raise HTTPException(400, "Invalid id")
    path = DELIVERIES_DIR / f"{delivery_id}.json"
    if not path.exists():
        raise HTTPException(404, "Delivery not found")
    path.unlink()
    return Response(status_code=204)


@app.delete("/api/deliveries", status_code=204)
def api_clear_deliveries(_: str = Depends(require_auth)) -> Response:
    for f in DELIVERIES_DIR.glob("*.json"):
        try:
            f.unlink()
        except OSError:
            pass
    return Response(status_code=204)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> None:
    global AUTH_USER, AUTH_PASSWORD, MAX_SKEW_SECONDS
    global DATA_DIR, SECRETS_FILE, DELIVERIES_DIR

    parser = argparse.ArgumentParser(
        description="Webhook delivery tester (files only, no DB)."
    )
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8095)
    parser.add_argument(
        "--user", default=os.environ.get("WEBHOOK_TESTER_USER", "admin")
    )
    parser.add_argument(
        "--password", default=os.environ.get("WEBHOOK_TESTER_PASSWORD", "admin")
    )
    parser.add_argument(
        "--data-dir",
        default=os.environ.get("WEBHOOK_TESTER_DATA", "/data"),
        help="Directory where secrets.json and deliveries/ are stored.",
    )
    parser.add_argument(
        "--max-skew",
        type=int,
        default=5 * 60,
        help="Reject deliveries whose timestamp is older than N seconds. 0 disables the check.",
    )
    args = parser.parse_args()

    AUTH_USER = args.user
    AUTH_PASSWORD = args.password
    MAX_SKEW_SECONDS = None if args.max_skew == 0 else args.max_skew

    DATA_DIR = Path(args.data_dir).resolve()
    SECRETS_FILE = DATA_DIR / "secrets.json"
    DELIVERIES_DIR = DATA_DIR / "deliveries"
    _ensure_dirs()

    logger.info(f"Data dir      : {DATA_DIR}")
    logger.info(f"Basic auth user: {AUTH_USER}")
    logger.info(
        f"Max skew      : {'disabled' if MAX_SKEW_SECONDS is None else f'{MAX_SKEW_SECONDS}s'}"
    )
    logger.info(f"Listening on  : http://{args.host}:{args.port}")

    uvicorn.run(app, host=args.host, port=args.port, log_level="info")


if __name__ == "__main__":
    main()
