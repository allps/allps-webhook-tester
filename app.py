from __future__ import annotations

import argparse
import hashlib
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
from fastapi import Cookie, Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import HTMLResponse
from loguru import logger

# ---------------------------------------------------------------------------
# .env loader
# ---------------------------------------------------------------------------


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
# Config
# ---------------------------------------------------------------------------

SIGNATURE_HEADER = "x-webhook-signature"
TIMESTAMP_HEADER = "x-webhook-timestamp"

BASE_DIR = Path(__file__).resolve().parent
INDEX_FILE = BASE_DIR / "static" / "index.html"

DATA_DIR = Path(os.environ.get("WEBHOOK_TESTER_DATA", "/data")).resolve()
ACCOUNTS_FILE = DATA_DIR / "accounts.json"
SECRETS_FILE = DATA_DIR / "secrets.json"
DELIVERIES_DIR = DATA_DIR / "deliveries"

MAX_SKEW_SECONDS: int | None = 5 * 60
SESSION_COOKIE = "whs_session"

_lock = threading.RLock()


def _ensure_dirs() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    DELIVERIES_DIR.mkdir(parents=True, exist_ok=True)
    for f in (ACCOUNTS_FILE, SECRETS_FILE):
        if not f.exists():
            f.write_text("[]", encoding="utf-8")


_ensure_dirs()


# ---------------------------------------------------------------------------
# File storage
# ---------------------------------------------------------------------------


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _read_json_list(path: Path) -> list[dict[str, Any]]:
    with _lock:
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (FileNotFoundError, json.JSONDecodeError):
            return []


def _write_json_list(path: Path, items: list[dict[str, Any]]) -> None:
    with _lock:
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(json.dumps(items, indent=2), encoding="utf-8")
        tmp.replace(path)


# accounts -----------------------------------------------------------------


def load_accounts() -> list[dict[str, Any]]:
    return _read_json_list(ACCOUNTS_FILE)


def save_accounts(items: list[dict[str, Any]]) -> None:
    _write_json_list(ACCOUNTS_FILE, items)


def find_account_by_username(username: str) -> dict[str, Any] | None:
    username = username.lower()
    for a in load_accounts():
        if a["username"].lower() == username:
            return a
    return None


def find_account_by_id(account_id: str) -> dict[str, Any] | None:
    for a in load_accounts():
        if a["id"] == account_id:
            return a
    return None


# secrets ------------------------------------------------------------------


def load_secrets() -> list[dict[str, Any]]:
    return _read_json_list(SECRETS_FILE)


def save_secrets(items: list[dict[str, Any]]) -> None:
    _write_json_list(SECRETS_FILE, items)


# deliveries ---------------------------------------------------------------


def save_delivery(d: dict[str, Any]) -> None:
    path = DELIVERIES_DIR / f"{d['id']}.json"
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(d, indent=2), encoding="utf-8")
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
    files = list(DELIVERIES_DIR.glob("*.json"))
    files.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    return files[:limit]


# ---------------------------------------------------------------------------
# Password hashing
# ---------------------------------------------------------------------------

_PBKDF2_ITERATIONS = 200_000


def hash_password(password: str) -> str:
    salt = pysecrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, _PBKDF2_ITERATIONS
    )
    return f"pbkdf2_sha256${_PBKDF2_ITERATIONS}${salt.hex()}${dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, iters_s, salt_hex, hash_hex = stored.split("$")
        if algo != "pbkdf2_sha256":
            return False
        dk = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), bytes.fromhex(salt_hex), int(iters_s)
        )
        return hmac.compare_digest(dk.hex(), hash_hex)
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Sessions (in-memory; restart = everyone logs out)
# ---------------------------------------------------------------------------

_sessions: dict[str, str] = {}  # session_id -> account_id


def create_session(account_id: str) -> str:
    sid = pysecrets.token_urlsafe(32)
    _sessions[sid] = account_id
    return sid


def destroy_session(sid: str | None) -> None:
    if sid:
        _sessions.pop(sid, None)


def current_account(
    session: str | None = Cookie(default=None, alias=SESSION_COOKIE),
) -> dict[str, Any]:
    if not session:
        raise HTTPException(401, "Not authenticated")
    account_id = _sessions.get(session)
    if not account_id:
        raise HTTPException(401, "Session expired")
    account = find_account_by_id(account_id)
    if not account:
        raise HTTPException(401, "Account no longer exists")
    return account


# ---------------------------------------------------------------------------
# HMAC verification
# ---------------------------------------------------------------------------


class WebhookVerificationError(Exception):
    pass


def verify_webhook_signature(secret, raw_body, headers, *, max_skew_seconds):
    sig = headers.get(SIGNATURE_HEADER)
    ts = headers.get(TIMESTAMP_HEADER)
    if not sig:
        raise WebhookVerificationError(f"Missing {SIGNATURE_HEADER} header")
    if not ts:
        raise WebhookVerificationError(f"Missing {TIMESTAMP_HEADER} header")
    if max_skew_seconds is not None:
        try:
            age = abs(int(time.time()) - int(ts))
        except (TypeError, ValueError):
            raise WebhookVerificationError(f"Invalid {TIMESTAMP_HEADER}: {ts!r}")
        if age > max_skew_seconds:
            raise WebhookVerificationError(
                f"Timestamp too old ({age}s > {max_skew_seconds}s)"
            )
    signed = ts.encode("utf-8") + b"." + raw_body
    expected = "sha256=" + hmac.new(secret.encode("utf-8"), signed, sha256).hexdigest()
    if not hmac.compare_digest(expected, sig):
        raise WebhookVerificationError("Signature mismatch")


def verify_against_all(
    raw_body, headers
) -> tuple[bool, str | None, str | None, str | None, str | None]:
    """Return (verified, matched_secret_name, matched_secret_id, matched_account_id, error)."""
    configured = load_secrets()
    if not configured:
        return False, None, None, None, "No signing secrets configured"
    last_error = "Signature mismatch"
    for entry in configured:
        try:
            verify_webhook_signature(
                entry["value"], raw_body, headers, max_skew_seconds=MAX_SKEW_SECONDS
            )
            return True, entry["name"], entry["id"], entry.get("account_id"), None
        except WebhookVerificationError as exc:
            last_error = str(exc)
        except Exception as exc:
            last_error = f"Unexpected error: {exc}"
    return False, None, None, None, last_error


# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------

app = FastAPI(title="Webhook Delivery Tester", docs_url=None, redoc_url=None)


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

    verified, matched, matched_secret_id, account_id, error = verify_against_all(
        raw_body, req.headers
    )

    delivery = {
        "id": uuid.uuid4().hex,
        "account_id": account_id,
        "received_at": _now_iso(),
        "client": req.client.host if req.client else None,
        "event": req.headers.get("x-webhook-event"),
        "headers": dict(req.headers),
        "body": parsed,
        "raw_body": raw_body.decode("utf-8", errors="replace"),
        "verified": verified,
        "matched_secret": matched,
        "matched_secret_id": matched_secret_id,
        "verification_error": None if verified else error,
    }

    save_delivery(delivery)

    if verified:
        logger.info(f"Delivery {delivery['id']} verified (account={account_id})")
    else:
        logger.warning(f"Delivery {delivery['id']} FAILED: {error}")

    return {"status": "ok", "verified": verified, "delivery_id": delivery["id"]}


# ---- UI ------------------------------------------------------------------


@app.get("/", response_class=HTMLResponse)
def index() -> HTMLResponse:
    return HTMLResponse(INDEX_FILE.read_text(encoding="utf-8"))


# ---- Auth API ------------------------------------------------------------


@app.post("/api/auth/register")
def api_register(payload: dict[str, Any], response: Response) -> dict[str, Any]:
    username = (payload.get("username") or "").strip()
    password = payload.get("password") or ""
    if len(username) < 3 or len(password) < 6:
        raise HTTPException(400, "username must be >=3 chars, password >=6 chars")
    if find_account_by_username(username):
        raise HTTPException(409, "Username already taken")

    account = {
        "id": uuid.uuid4().hex,
        "username": username,
        "password_hash": hash_password(password),
        "created_at": _now_iso(),
    }
    accounts = load_accounts()
    accounts.append(account)
    save_accounts(accounts)

    sid = create_session(account["id"])
    response.set_cookie(
        SESSION_COOKIE, sid, httponly=True, samesite="lax", max_age=30 * 24 * 3600
    )
    return {"id": account["id"], "username": account["username"]}


@app.post("/api/auth/login")
def api_login(payload: dict[str, Any], response: Response) -> dict[str, Any]:
    username = (payload.get("username") or "").strip()
    password = payload.get("password") or ""
    account = find_account_by_username(username)
    if not account or not verify_password(password, account["password_hash"]):
        raise HTTPException(401, "Invalid credentials")

    sid = create_session(account["id"])
    response.set_cookie(
        SESSION_COOKIE, sid, httponly=True, samesite="lax", max_age=30 * 24 * 3600
    )
    return {"id": account["id"], "username": account["username"]}


@app.post("/api/auth/logout")
def api_logout(
    response: Response,
    session: str | None = Cookie(default=None, alias=SESSION_COOKIE),
) -> dict[str, str]:
    destroy_session(session)
    response.delete_cookie(SESSION_COOKIE)
    return {"status": "ok"}


@app.get("/api/auth/me")
def api_me(account: dict[str, Any] = Depends(current_account)) -> dict[str, Any]:
    return {"id": account["id"], "username": account["username"]}


# ---- Secrets API ---------------------------------------------------------


@app.get("/api/secrets")
def api_list_secrets(
    account: dict[str, Any] = Depends(current_account),
) -> list[dict[str, Any]]:
    return [
        {
            "id": s["id"],
            "name": s["name"],
            "value": s["value"],
            "created_at": s.get("created_at"),
        }
        for s in load_secrets()
        if s.get("account_id") == account["id"]
    ]


@app.post("/api/secrets", status_code=201)
def api_add_secret(
    payload: dict[str, Any],
    account: dict[str, Any] = Depends(current_account),
) -> dict[str, Any]:
    name = (payload.get("name") or "").strip()
    value = (payload.get("value") or "").strip()
    if not name or not value:
        raise HTTPException(400, "'name' and 'value' are both required")

    items = load_secrets()
    entry = {
        "id": uuid.uuid4().hex,
        "account_id": account["id"],
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
def api_delete_secret(
    secret_id: str,
    account: dict[str, Any] = Depends(current_account),
) -> Response:
    items = load_secrets()
    target = next((s for s in items if s["id"] == secret_id), None)
    if not target or target.get("account_id") != account["id"]:
        raise HTTPException(404, "Secret not found")
    save_secrets([s for s in items if s["id"] != secret_id])
    return Response(status_code=204)


# ---- Deliveries API ------------------------------------------------------


def _visible(d: dict[str, Any], account_id: str) -> bool:
    return d.get("account_id") == account_id


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
        "matched_secret_id": d.get("matched_secret_id"),
        "event": d.get("event") or headers.get("x-webhook-event"),
        "interview_id": interview.get("id"),
        "interview_kind": interview.get("kind"),
    }


@app.get("/api/deliveries")
def api_list_deliveries(
    limit: int = 100,
    account: dict[str, Any] = Depends(current_account),
) -> list[dict[str, Any]]:
    limit = max(1, min(limit, 500))
    out: list[dict[str, Any]] = []
    for path in list_delivery_files(500):
        try:
            d = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        if not _visible(d, account["id"]):
            continue
        out.append(delivery_summary(d))
        if len(out) >= limit:
            break
    return out


@app.get("/api/deliveries/{delivery_id}")
def api_get_delivery(
    delivery_id: str,
    account: dict[str, Any] = Depends(current_account),
) -> dict[str, Any]:
    d = load_delivery(delivery_id)
    if d is None or not _visible(d, account["id"]):
        raise HTTPException(404, "Delivery not found")
    return d


@app.get("/api/deliveries/{delivery_id}/download")
def api_download_delivery(
    delivery_id: str,
    account: dict[str, Any] = Depends(current_account),
) -> Response:
    d = load_delivery(delivery_id)
    if d is None or not _visible(d, account["id"]):
        raise HTTPException(404, "Delivery not found")
    return Response(
        content=d.get("raw_body") or "",
        media_type="application/json",
        headers={
            "Content-Disposition": f'attachment; filename="delivery_{delivery_id}.json"'
        },
    )


@app.delete("/api/deliveries/{delivery_id}", status_code=204)
def api_delete_delivery(
    delivery_id: str,
    account: dict[str, Any] = Depends(current_account),
) -> Response:
    if not delivery_id.isalnum():
        raise HTTPException(400, "Invalid id")
    path = DELIVERIES_DIR / f"{delivery_id}.json"
    if not path.exists():
        raise HTTPException(404, "Delivery not found")
    try:
        d = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        raise HTTPException(500, "Corrupt delivery")
    if not _visible(d, account["id"]):
        raise HTTPException(404, "Delivery not found")
    path.unlink()
    return Response(status_code=204)


@app.delete("/api/deliveries", status_code=204)
def api_clear_deliveries(
    account: dict[str, Any] = Depends(current_account),
) -> Response:
    for f in DELIVERIES_DIR.glob("*.json"):
        try:
            d = json.loads(f.read_text(encoding="utf-8"))
        except Exception:
            continue
        if _visible(d, account["id"]):
            try:
                f.unlink()
            except OSError:
                pass
    return Response(status_code=204)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> None:
    global MAX_SKEW_SECONDS, DATA_DIR, ACCOUNTS_FILE, SECRETS_FILE, DELIVERIES_DIR

    parser = argparse.ArgumentParser(
        description="Webhook delivery tester (multi-account, no DB)."
    )
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8095)
    parser.add_argument(
        "--data-dir",
        default=os.environ.get("WEBHOOK_TESTER_DATA", "/data"),
        help="Directory where accounts.json, secrets.json and deliveries/ are stored.",
    )
    parser.add_argument(
        "--max-skew",
        type=int,
        default=5 * 60,
        help="Reject deliveries whose timestamp is older than N seconds. 0 disables the check.",
    )
    args = parser.parse_args()

    MAX_SKEW_SECONDS = None if args.max_skew == 0 else args.max_skew

    DATA_DIR = Path(args.data_dir).resolve()
    ACCOUNTS_FILE = DATA_DIR / "accounts.json"
    SECRETS_FILE = DATA_DIR / "secrets.json"
    DELIVERIES_DIR = DATA_DIR / "deliveries"
    _ensure_dirs()

    logger.info(f"Data dir      : {DATA_DIR}")
    logger.info(
        f"Max skew      : {'disabled' if MAX_SKEW_SECONDS is None else f'{MAX_SKEW_SECONDS}s'}"
    )
    logger.info(f"Listening on  : http://{args.host}:{args.port}")

    uvicorn.run(app, host=args.host, port=args.port, log_level="info")


if __name__ == "__main__":
    main()
