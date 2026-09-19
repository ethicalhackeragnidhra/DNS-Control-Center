from __future__ import annotations

from datetime import datetime, timezone
from functools import wraps
import hmac
import json

from dotenv import load_dotenv
from flask import Flask, jsonify, redirect, render_template, request, session, url_for

from .config import Config
from .db import audit, audit_for_domain, delete_exception, get_exception, init_db, list_exceptions, upsert_exception, ingest_live_logs
from .providers import ProviderManager

load_dotenv()
config = Config()
app = Flask(__name__, template_folder="../templates", static_folder="../static")
app.secret_key = config.flask_secret_key
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=False,
)
init_db()
manager = ProviderManager(config)
manager.start_live_worker()


def login_required(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        if not session.get("authenticated"):
            if request.path.startswith("/api/"):
                return jsonify({"error": "authentication required"}), 401
            return redirect(url_for("login", next=request.path))
        return fn(*args, **kwargs)

    return wrapped


@app.get("/login")
def login():
    return render_template("login.html", app_name=config.app_name)


@app.post("/login")
def do_login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    if username == config.admin_username and password == config.admin_password:
        session.clear()
        session["authenticated"] = True
        return redirect(request.form.get("next") or "/")
    return render_template("login.html", app_name=config.app_name, error="Invalid credentials"), 401


@app.post("/logout")
@login_required
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.get("/")
@login_required
def index():
    return render_template("index.html", app_name=config.app_name)


@app.get("/activity")
@login_required
def activity_page():
    return render_template("activity.html", app_name=config.app_name, live_poll_seconds=config.live_poll_seconds)


@app.get("/policies")
@login_required
def policies_page():
    return render_template("policies.html", app_name=config.app_name)


@app.get("/api/status")
@login_required
def api_status():
    return jsonify(
        {
            "providers": manager.status(),
            "exceptions": len(list_exceptions()),
            "app": config.app_name,
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }
    )


@app.get("/api/analytics")
@login_required
def api_analytics():
    raw = request.args.get("hours", str(config.log_window_hours))
    try:
        hours = max(1, min(int(raw), 168))
    except ValueError:
        return jsonify({"error": "hours must be an integer"}), 400
    return jsonify(manager.analytics(hours))


@app.get("/api/blocked")
@login_required
def api_blocked():
    raw = request.args.get("hours", str(config.log_window_hours))
    try:
        hours = max(1, min(int(raw), 168))
    except ValueError:
        return jsonify({"error": "hours must be an integer"}), 400
    return jsonify(manager.blocked(hours))


@app.get("/api/logs")
@login_required
def api_logs():
    try:
        minutes = max(1, min(int(request.args.get("minutes", "5")), 60))
        limit = max(1, min(int(request.args.get("limit", "500")), 2000))
    except ValueError:
        return jsonify({"error": "minutes and limit must be integers"}), 400
    provider = request.args.get("provider", "all")
    status = request.args.get("status", "all")
    search = request.args.get("search", "").strip()
    fresh = request.args.get("fresh", "0").strip().lower() in {"1", "true", "yes"}
    try:
        payload = manager.live_logs(minutes=minutes, limit=limit, provider=provider, status=status, search=search, fresh=fresh)
        return jsonify(payload)
    except Exception as exc:
        # Live traffic is supplemental: an ingestion/provider failure must never take down
        # the overview or activity pages. Return a valid payload with the error surfaced.
        return jsonify({
            "rows": [],
            "messages": {"console": str(exc)},
            "refreshed_at": None,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "ok": False,
        })


@app.post("/api/ingest/controld")
def api_ingest_controld():
    secret = config.controld_log_ingest_secret.strip()
    supplied = request.headers.get("X-DNS-Control-Ingest", "")
    if not secret or not hmac.compare_digest(supplied, secret):
        return jsonify({"error": "invalid ingest token"}), 401
    payload = request.get_json(silent=True)
    if payload is None:
        try:
            payload = json.loads(request.data.decode("utf-8"))
        except Exception:
            payload = None
    items = payload if isinstance(payload, list) else [payload]
    normalized = []
    for item in items:
        if not isinstance(item, dict):
            continue
        action_code = item.get("controld_action")
        try:
            action_code = int(action_code)
        except Exception:
            action_code = None
        if action_code == 0:
            action = "blocked"
        elif action_code == -1:
            action = "error"
        else:
            action = "allowed"
        query_obj = item.get("query") if isinstance(item.get("query"), dict) else {}
        domain = item.get("domain") or query_obj.get("domain") or query_obj.get("host") or ""
        timestamp = item.get("timestamp") or item.get("time") or item.get("datetime") or datetime.now(timezone.utc).isoformat()
        device = item.get("device") or {}
        client = item.get("client") or {}
        if isinstance(client, dict):
            client_name = client.get("name") or client.get("id") or ""
        else:
            client_name = str(client)
        if not client_name:
            src = item.get("source_ip") or item.get("client_ip") or ""
            client_name = src if isinstance(src, str) else json.dumps(src, default=str)
        if isinstance(device, dict):
            device_name = device.get("name") or device.get("id") or ""
        else:
            device_name = str(device)
        answers = item.get("answers") if isinstance(item.get("answers"), dict) else {}
        geoip = answers.get("geoip") if isinstance(answers.get("geoip"), dict) else {}
        normalized.append({
            "timestamp": timestamp,
            "domain": domain,
            "action": action,
            "reason": item.get("controld_trigger_name") or item.get("controld_trigger") or "",
            "client": client_name,
            "device": device_name,
            "protocol": item.get("protocol") or item.get("dns_protocol") or "",
            "country": geoip.get("country") or item.get("country") or "",
            "detail": json.dumps(item, separators=(",", ":"), default=str),
        })
    accepted = ingest_live_logs("Control D", normalized)
    return jsonify({"ok": True, "accepted": accepted})


@app.get("/api/policies")
@login_required
def api_policies():
    return jsonify({"providers": manager.policies(), "generated_at": datetime.now(timezone.utc).isoformat()})


@app.get("/api/exceptions")
@login_required
def api_exceptions():
    return jsonify({"items": list_exceptions()})


@app.get("/api/domain/<path:domain>")
@login_required
def api_domain(domain):
    try:
        state = manager.provider_exception_state(domain)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    return jsonify(
        {
            "domain": domain,
            "exception": get_exception(domain),
            "providers": state,
            "audit": audit_for_domain(domain),
        }
    )


def _parse_rule_body():
    body = request.get_json(silent=True) or {}
    domain = (body.get("domain") or "").strip().lower().rstrip(".")
    action = (body.get("action") or "allow").strip().lower()
    scope = (body.get("scope") or "all").strip()
    note = (body.get("note") or "").strip()
    if action not in {"allow", "block"}:
        raise ValueError("action must be allow or block")
    if not domain:
        raise ValueError("domain is required")
    return domain, action, scope, note


@app.post("/api/policy/add")
@login_required
def api_policy_add():
    try:
        domain, action, scope, note = _parse_rule_body()
        results = manager.add_rule(domain, action, scope)
    except Exception as exc:
        return jsonify({"error": str(exc)}), 400
    for result in results:
        audit(domain, action, result["provider"], result.get("ok", False), result.get("error", ""))
    if scope == "all":
        if action == "allow":
            upsert_exception(domain, note or "Added from Policy Manager")
        elif action == "block":
            delete_exception(domain)
    return jsonify({"domain": domain, "action": action, "scope": scope, "results": results})


@app.post("/api/policy/remove")
@login_required
def api_policy_remove():
    try:
        domain, action, scope, _note = _parse_rule_body()
        results = manager.remove_rule(domain, action, scope)
    except Exception as exc:
        return jsonify({"error": str(exc)}), 400
    for result in results:
        audit(domain, f"remove-{action}", result["provider"], result.get("ok", False), result.get("error", ""))
    if action == "allow" and scope == "all":
        delete_exception(domain)
    return jsonify({"domain": domain, "action": action, "scope": scope, "results": results})


@app.post("/api/allow")
@login_required
def api_allow():
    body = request.get_json(silent=True) or {}
    body["action"] = "allow"
    request._cached_json = (body, body)
    return api_policy_add()


@app.post("/api/remove")
@login_required
def api_remove():
    body = request.get_json(silent=True) or {}
    body["action"] = "allow"
    request._cached_json = (body, body)
    return api_policy_remove()


@app.post("/api/sync")
@login_required
def api_sync():
    manager.cache = {"at": 0.0, "payload": None}
    return jsonify({"ok": True})


@app.get("/health")
def health():
    return jsonify({"ok": True})
