from __future__ import annotations

import csv
import io
import re
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import quote

import requests

from .config import Config
from .db import ingest_live_logs, list_exceptions, recent_live_logs

TIMEOUT = 15
MAX_RULES_DISPLAY = 5000


def _num(value: Any, default: float = 0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _series_times(payload: dict[str, Any]) -> list[str]:
    return list((((payload or {}).get("meta") or {}).get("series") or {}).get("times") or [])


def _series_rows(payload: dict[str, Any], value_keys=("queries", "count", "value")) -> list[dict[str, Any]]:
    times = _series_times(payload)
    rows: list[dict[str, Any]] = []
    for item in (payload or {}).get("data", []) or []:
        values = None
        for key in value_keys:
            if isinstance(item.get(key), list):
                values = item[key]
                break
        if values is None:
            continue
        label = item.get("name") or item.get("status") or item.get("id") or item.get("domain") or "value"
        for i, value in enumerate(values):
            if i < len(times):
                rows.append({"time": times[i], "label": str(label), "value": _num(value)})
    return rows


def _stat_items(payload: dict[str, Any]) -> list[dict[str, Any]]:
    for key in ("stats", "data", "items"):
        value = (payload or {}).get(key)
        if isinstance(value, list):
            return value
    return []


def _stat_rows(payload: dict[str, Any], label_keys=("name", "id", "domain", "country", "code", "device", "company", "category", "company_name", "device_id", "category_type")) -> list[dict[str, Any]]:
    out=[]
    for item in _stat_items(payload):
        if not isinstance(item, dict):
            continue
        value_obj = item.get("value") if isinstance(item.get("value"), dict) else item
        label = None
        for k in label_keys:
            if item.get(k) not in (None, ""):
                label = item.get(k)
                break
        if label is None and value_obj is not item:
            for k in label_keys:
                if value_obj.get(k) not in (None, ""):
                    label = value_obj.get(k)
                    break
        if label is None:
            continue
        value = None
        for k in ("queries", "count", "value", "requests"):
            if value_obj.get(k) is not None and not isinstance(value_obj.get(k), (dict, list)):
                value = _num(value_obj.get(k))
                break
        if value is not None:
            out.append({"label": str(label), "value": value, "blocked": _num(value_obj.get("blocked")), **item})
    return out


def _top_named(payload: dict[str, Any], limit: int = 25) -> list[dict[str, Any]]:
    rows = _stat_rows(payload)
    rows.sort(key=lambda x: x["value"], reverse=True)
    return [{"name": x["label"], "value": int(x["value"])} for x in rows[:limit]]


def _iso_hour(ts: Any) -> str | None:
    if not ts:
        return None
    try:
        d = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
        d = d.astimezone(timezone.utc).replace(minute=0, second=0, microsecond=0)
        return d.isoformat().replace("+00:00", "Z")
    except (TypeError, ValueError):
        return None

def _bucket_timeline(rows: list[dict[str, Any]], bucket_seconds: int = 3600) -> dict[str, dict[str, Any]]:
    """Aggregate provider-native buckets onto one common UTC grid. Missing buckets stay missing."""
    out: dict[str, dict[str, Any]] = {}
    if not rows:
        return out
    bucket_seconds = max(60, int(bucket_seconds))
    epoch = datetime(1970, 1, 1, tzinfo=timezone.utc).timestamp()
    for row in rows:
        try:
            dt = datetime.fromisoformat(str(row.get("time")).replace("Z", "+00:00")).astimezone(timezone.utc)
        except Exception:
            continue
        ts = int(dt.timestamp())
        floored = epoch + ((ts - int(epoch)) // bucket_seconds) * bucket_seconds
        key = datetime.fromtimestamp(floored, tz=timezone.utc).isoformat().replace("+00:00", "Z")
        b = out.setdefault(key, {"time": key, "queries": 0, "blocked": 0, "allowed": 0})
        q = int(_num(row.get("queries")))
        b["queries"] += q
        b["blocked"] += int(_num(row.get("blocked")))
        b["allowed"] += int(_num(row.get("allowed"), max(0, q - int(_num(row.get("blocked"))))))
    return out

def _common_combined_timeline(provider_results: list[dict[str, Any]], bucket_seconds: int = 3600) -> list[dict[str, Any]]:
    """Return aligned per-provider rows on the same time grid; never invent zeros for missing data."""
    by_provider: dict[str, dict[str, dict[str, Any]]] = {}
    all_times: set[str] = set()
    for p in provider_results:
        rows = _bucket_timeline(p.get("timeline") or [], bucket_seconds)
        by_provider[p.get("provider", "Provider")] = rows
        all_times.update(rows.keys())
    ordered = sorted(all_times)
    combined = []
    for t in ordered:
        item = {"time": t, "providers": {}}
        for name, rows in by_provider.items():
            if t in rows:
                item["providers"][name] = rows[t]
        combined.append(item)
    return combined


def _domain(value: str) -> str:
    value = (value or "").strip().lower().rstrip(".")
    value = re.sub(r"^https?://", "", value)
    value = value.split("/", 1)[0].split(":", 1)[0]
    if value.startswith("*."):
        value = value[2:]
    if not value or "." not in value or any(c.isspace() for c in value) or len(value) > 253:
        raise ValueError("Enter a valid hostname, e.g. example.com")
    return value


def _json(resp: requests.Response) -> Any:
    try:
        data = resp.json()
    except ValueError:
        data = {"raw": resp.text}
    if not resp.ok:
        raise RuntimeError(f"HTTP {resp.status_code}: {str(data)[:700]}")
    if isinstance(data, dict) and data.get("errors"):
        raise RuntimeError("; ".join(str(e.get("detail", e)) for e in data["errors"]))
    return data


def _rule_domain(rule: str) -> str | None:
    """Extract a useful domain from common AdGuard-style user rules."""
    s = (rule or "").strip()
    if not s or s.startswith("!") or s.startswith("#"):
        return None
    s = re.sub(r"^@@", "", s)
    m = re.search(r"\|\|([^|\^/$*]+)", s)
    if m:
        return m.group(1).lower().rstrip(".")
    if re.fullmatch(r"\*\.[A-Za-z0-9.-]+|[A-Za-z0-9.-]+", s):
        return s.lower().rstrip(".")
    return None


def _normalize_rules(rules: list[str]) -> dict[str, list[dict[str, str]]]:
    out = {"allow": [], "block": [], "other": []}
    seen: set[tuple[str, str]] = set()
    for rule in rules:
        raw = str(rule).strip()
        if not raw or raw.startswith("!") or raw.startswith("#"):
            continue
        domain = _rule_domain(raw)
        if raw.startswith("@@"):
            kind = "allow"
        elif domain:
            kind = "block"
        else:
            kind = "other"
        key = (kind, raw)
        if key in seen:
            continue
        seen.add(key)
        out[kind].append({"domain": domain or raw, "rule": raw})
    for k in out:
        out[k] = out[k][:MAX_RULES_DISPLAY]
    return out


class BaseProvider:
    name = "Provider"

    def policy(self) -> dict[str, Any]:
        return {"name": self.name, "allow": [], "block": [], "other": [], "lists": []}

    def analytics(self, hours: int) -> dict[str, Any]:
        enabled = bool(getattr(self, "enabled", False))
        return {
            "provider": self.name,
            "configured": enabled,
            "error": None if not enabled else "Analytics not implemented for this provider",
            "timeline": [],
            "reasons": [],
            "domains": [],
            "devices": [],
            "protocols": [],
            "countries": [],
        }

    def recent_logs(self, minutes: int = 5, limit: int = 300):
        return [], f"{self.name} live query log is not available through the configured API"

    def add_rule(self, domain: str, action: str):
        raise NotImplementedError

    def set_rule(self, domain: str, action: str):
        """Set an exclusive state: remove the opposite state before applying the desired one."""
        return self.add_rule(domain, action)

    def remove_rule(self, domain: str, action: str):
        raise NotImplementedError


class NextDNS(BaseProvider):
    name = "NextDNS"

    def __init__(self, c: Config):
        self.c = c
        self.base = "https://api.nextdns.io"

    @property
    def enabled(self):
        return self.c.nextdns_enabled and bool(self.c.nextdns_api_key and self.c.nextdns_profile_id)

    def headers(self):
        return {"X-Api-Key": self.c.nextdns_api_key, "Accept": "application/json"}

    def profile(self):
        if not self.enabled:
            return {}
        r = requests.get(f"{self.base}/profiles/{self.c.nextdns_profile_id}", headers=self.headers(), timeout=TIMEOUT)
        return _json(r).get("data", {})

    def status(self):
        if not self.enabled:
            return {"enabled": False, "configured": False, "name": self.name}
        p = self.profile()
        return {"enabled": True, "configured": True, "name": self.name, "profile": p.get("name", self.c.nextdns_profile_id), "profile_id": self.c.nextdns_profile_id}

    def _list(self, kind: str):
        p = self.profile()
        return list(p.get(kind, []))

    def allowlist(self):
        return self._list("allowlist")

    def denylist(self):
        return self._list("denylist")

    def policy(self):
        if not self.enabled:
            return {"name": self.name, "allow": [], "block": [], "other": [], "lists": [], "configured": False}
        p = self.profile()
        allow = [{"domain": x.get("id", ""), "rule": x.get("id", ""), "active": bool(x.get("active", True))} for x in p.get("allowlist", [])]
        block = [{"domain": x.get("id", ""), "rule": x.get("id", ""), "active": bool(x.get("active", True))} for x in p.get("denylist", [])]
        lists = []
        for x in (p.get("privacy", {}) or {}).get("blocklists", []) or []:
            lists.append({"type": "blocklist", "id": x.get("id", ""), "enabled": bool(x.get("active", True))})
        return {"name": self.name, "configured": True, "allow": allow, "block": block, "other": [], "lists": lists, "profile": p.get("name", self.c.nextdns_profile_id)}

    def analytics(self, hours: int) -> dict[str, Any]:
        empty = {"provider": self.name, "configured": True, "timeline": [], "reasons": [], "domains": [], "devices": [], "protocols": [], "countries": [], "partial_errors": {}}
        if not self.enabled:
            empty["configured"] = False
            empty["error"] = "Not configured"
            return empty

        from_value = f"-{hours}h"
        interval = 900 if hours <= 6 else (3600 if hours <= 72 else 21600)
        partial_errors = {}

        def get(path: str, params: dict[str, Any] | None = None):
            r = requests.get(
                f"{self.base}/profiles/{self.c.nextdns_profile_id}/analytics/{path}",
                headers=self.headers(),
                params=params or {"from": from_value, "limit": 100},
                timeout=TIMEOUT,
            )
            return _json(r)

        # Status is the only required call for the headline/timeline.
        status = get("status;series", {"from": from_value, "interval": interval, "partials": "all", "limit": 100})
        extras = {}
        endpoints = {
            "reasons": ("reasons", {"from": from_value, "limit": 25}),
            "domains": ("domains", {"from": from_value, "limit": 25}),
            "devices": ("devices", {"from": from_value, "limit": 25}),
            "protocols": ("protocols", {"from": from_value, "limit": 25}),
            "countries": ("destinations", {"from": from_value, "type": "countries", "limit": 50}),
        }
        for key, (path, params) in endpoints.items():
            try:
                extras[key] = get(path, params)
            except Exception as exc:
                partial_errors[key] = str(exc)
                extras[key] = {"data": []}

        series = {}
        for row in _series_rows(status):
            bucket = series.setdefault(row["time"], {"time": row["time"], "queries": 0, "blocked": 0, "allowed": 0})
            bucket["queries"] += int(row["value"])
            label = row["label"].lower()
            if label == "blocked":
                bucket["blocked"] += int(row["value"])
            elif label in ("allowed", "default"):
                bucket["allowed"] += int(row["value"])

        def data_rows(name: str, label_keys: tuple[str, ...]) -> list[dict[str, Any]]:
            out = []
            for item in (extras.get(name, {}) or {}).get("data", []) or []:
                label = next((item.get(k) for k in label_keys if item.get(k) not in (None, "")), None)
                if label is None:
                    continue
                out.append({"name": str(label), "value": int(_num(item.get("queries")))})
            return out

        return {
            "provider": self.name,
            "configured": True,
            "error": None,
            "partial_errors": partial_errors,
            "total_queries": int(sum(x["queries"] for x in series.values())),
            "blocked_queries": int(sum(x["blocked"] for x in series.values())),
            "timeline": list(sorted(series.values(), key=lambda x: x["time"])),
            "reasons": data_rows("reasons", ("name", "id")),
            "domains": data_rows("domains", ("domain",)),
            "devices": data_rows("devices", ("name", "id")),
            "protocols": data_rows("protocols", ("protocol",)),
            "countries": [{"code": x.get("code"), "value": int(_num(x.get("queries"))), "kind": "destination"} for x in (extras.get("countries", {}) or {}).get("data", []) if x.get("code")],
        }

    def blocked_logs(self, hours: int):
        if not self.enabled:
            return [], "Not configured"
        r = requests.get(f"{self.base}/profiles/{self.c.nextdns_profile_id}/logs", headers=self.headers(), params={"from": f"-{hours}h", "status": "blocked", "limit": 1000, "raw": 0}, timeout=TIMEOUT)
        data = _json(r)
        rows = []
        for item in data.get("data", []):
            try:
                domain = _domain(item.get("domain", ""))
            except ValueError:
                continue
            rows.append({"provider": self.name, "domain": domain, "timestamp": item.get("timestamp"), "blocked": True, "reason": ", ".join(x.get("name", x.get("id", "")) for x in item.get("reasons", [])) or "Blocked", "detail": item.get("reasons", [])})
        return rows, None

    def recent_logs(self, minutes: int = 5, limit: int = 300):
        if not self.enabled:
            return [], "Not configured"
        end = datetime.now(timezone.utc)
        start = end - timedelta(minutes=max(1, minutes))
        r = requests.get(
            f"{self.base}/profiles/{self.c.nextdns_profile_id}/logs",
            headers=self.headers(),
            params={"from": start.isoformat().replace("+00:00", "Z"), "to": end.isoformat().replace("+00:00", "Z"), "sort": "desc", "limit": max(10, min(limit, 1000))},
            timeout=5,
        )
        data = _json(r)
        rows = []
        for item in data.get("data", []) or []:
            try:
                domain = _domain(item.get("domain", ""))
            except ValueError:
                continue
            status = str(item.get("status") or "default").lower()
            action = "blocked" if status == "blocked" else ("error" if status == "error" else "allowed")
            reasons = item.get("reasons") or []
            reason = ", ".join(str(x.get("name") or x.get("id") or "") for x in reasons if isinstance(x, dict)) or status
            device = item.get("device") or {}
            rows.append({"provider": self.name, "domain": domain, "timestamp": item.get("timestamp"), "action": action, "reason": reason, "client": item.get("clientIp") or item.get("clientIP") or "", "device": device.get("name") if isinstance(device, dict) else str(device or ""), "protocol": item.get("protocol") or "", "country": item.get("country") or item.get("destinationCountry") or "", "detail": item})
        return rows, None

    def _replace(self, endpoint: str, values: list[dict[str, Any]]):
        r = requests.put(f"{self.base}/profiles/{self.c.nextdns_profile_id}/{endpoint}", headers={**self.headers(), "Content-Type": "application/json"}, json=values, timeout=TIMEOUT)
        return _json(r)

    def _add(self, endpoint: str, domain: str):
        d = _domain(domain)
        r = requests.post(f"{self.base}/profiles/{self.c.nextdns_profile_id}/{endpoint}", headers={**self.headers(), "Content-Type": "application/json"}, json={"id": d, "active": True}, timeout=TIMEOUT)
        return _json(r)

    def add_rule(self, domain: str, action: str):
        return self.set_rule(domain, action)

    def set_rule(self, domain: str, action: str):
        d = _domain(domain)
        desired = "allowlist" if action == "allow" else "denylist"
        opposite = "denylist" if action == "allow" else "allowlist"
        current_opposite = self._list(opposite)
        if any(str(x.get("id", "")).lower() == d for x in current_opposite):
            self._replace(opposite, [x for x in current_opposite if str(x.get("id", "")).lower() != d])
        current = self._list(desired)
        match = next((x for x in current if str(x.get("id", "")).lower() == d), None)
        if match is not None:
            if not bool(match.get("active", True)):
                match["active"] = True
                return self._replace(desired, current)
            return {"ok": True, "unchanged": True}
        return self._add(desired, d)

    def remove_rule(self, domain: str, action: str):
        d = _domain(domain)
        endpoint = "allowlist" if action == "allow" else "denylist"
        current = self._list(endpoint)
        new = [x for x in current if str(x.get("id", "")).lower() != d]
        return self._replace(endpoint, new)

    def is_allowed(self, domain: str):
        d = _domain(domain)
        return any(str(x.get("id", "")).lower() == d and x.get("active", True) for x in self.allowlist())


class ControlD(BaseProvider):
    name = "Control D"

    def __init__(self, c: Config):
        self.c = c
        self.base = "https://api.controld.com"
        self._resolved_profile: str | None = None
        self._profiles_cache: list[dict[str, Any]] | None = None

    @property
    def enabled(self):
        return self.c.controld_enabled and bool(self.c.controld_api_token)

    def headers(self):
        h = {"Authorization": f"Bearer {self.c.controld_api_token}", "Accept": "application/json"}
        if self.c.controld_force_org_id:
            h["X-Force-Org-Id"] = self.c.controld_force_org_id
        return h

    def _profiles(self) -> list[dict[str, Any]]:
        if self._profiles_cache is not None:
            return self._profiles_cache
        r = requests.get(f"{self.base}/profiles", headers=self.headers(), timeout=TIMEOUT)
        body = _json(r)
        if not r.ok:
            raise RuntimeError(f"Control D profiles HTTP {r.status_code}: {(body.get('error') if isinstance(body, dict) else r.text) or r.text[:400]}")
        if not isinstance(body, dict):
            raise RuntimeError("Control D returned an unexpected /profiles response")
        profiles = ((body.get("body") or {}).get("profiles", []))
        if not isinstance(profiles, list):
            profiles = []
        self._profiles_cache = profiles
        return profiles

    def _profile_pk(self, p: dict[str, Any]) -> str:
        return str(p.get("PK") or p.get("pk") or p.get("id") or "")

    def _profile_summary(self, profiles: list[dict[str, Any]]) -> list[dict[str, str]]:
        return [{"name": str(p.get("name") or p.get("label") or "Unnamed"), "id": self._profile_pk(p)} for p in profiles if self._profile_pk(p)]

    def profile_id(self) -> str:
        if self._resolved_profile:
            return self._resolved_profile
        profiles = self._profiles()
        wanted = (self.c.controld_profile_id or "").strip()
        name_wanted = (self.c.controld_profile_name or "").strip().lower()
        found = None
        if wanted:
            found = next((p for p in profiles if self._profile_pk(p) == wanted), None)
        if found is None and name_wanted:
            found = next((p for p in profiles if str(p.get("name") or "").strip().lower() == name_wanted), None)
        if found is None and len(profiles) == 1:
            # Safe convenience: if the account exposes exactly one profile, use it even if
            # an old/incorrect ID was entered. This prevents a stale PK from breaking the app.
            found = profiles[0]
        if found is None:
            available = ", ".join(f"{x['name']} ({x['id']})" for x in self._profile_summary(profiles)) or "none"
            raise RuntimeError(f"Control D profile not found. Configured ID: {wanted or '(empty)'}. Available profiles: {available}")
        self._resolved_profile = self._profile_pk(found)
        return self._resolved_profile

    def status(self):
        if not self.enabled:
            return {"enabled": False, "configured": False, "name": self.name}
        try:
            profiles = self._profiles()
            pid = self.profile_id()
            p = next((p for p in profiles if self._profile_pk(p) == pid), {})
            return {
                "enabled": True, "configured": True, "name": self.name,
                "profile": p.get("name", pid), "profile_id": pid,
                "profile_source": "configured" if str(self.c.controld_profile_id).strip() == pid else "auto-resolved",
            }
        except Exception as e:
            return {"enabled": True, "configured": True, "name": self.name, "error": str(e)}

    def root_rules(self):
        pid = self.profile_id()
        r = requests.get(f"{self.base}/profiles/{quote(pid, safe='')}/rules", headers=self.headers(), timeout=TIMEOUT)
        body = _json(r)
        if not r.ok:
            raise RuntimeError(f"Control D rules HTTP {r.status_code}: {body}")
        return (body.get("body") or {}).get("rules", []) if isinstance(body, dict) else []

    def _groups(self):
        pid = self.profile_id()
        r = requests.get(f"{self.base}/profiles/{quote(pid, safe='')}/groups", headers=self.headers(), timeout=TIMEOUT)
        return ((r.json().get("body") or {}).get("groups", [])) if r.ok else []

    def _all_rules(self):
        rules = list(self.root_rules())
        try:
            pid = self.profile_id()
            for g in self._groups():
                gid = g.get("PK") or g.get("id")
                if gid is None:
                    continue
                r = requests.get(f"{self.base}/profiles/{quote(pid, safe='')}/rules/{quote(str(gid), safe='')}", headers=self.headers(), timeout=TIMEOUT)
                if r.ok:
                    rules.extend(((r.json().get("body") or {}).get("rules", [])))
        except Exception:
            pass
        return rules[:MAX_RULES_DISPLAY]

    def policy(self):
        if not self.enabled:
            return {"name": self.name, "allow": [], "block": [], "other": [], "lists": [], "configured": False}
        allow, block, other = [], [], []
        for rule in self._all_rules():
            hosts = rule.get("hostnames") or rule.get("hostname") or []
            if isinstance(hosts, str):
                hosts = [hosts]
            action = int(rule.get("do", -1)) if str(rule.get("do", "")).isdigit() else rule.get("do")
            for host in hosts:
                entry = {"domain": str(host).lower().rstrip("."), "rule": str(host), "status": rule.get("status", 1), "comment": rule.get("comment", ""), "group": rule.get("group")}
                if action in (1, "BYPASS"):
                    allow.append(entry)
                elif action in (0, "BLOCK"):
                    block.append(entry)
                else:
                    other.append({**entry, "action": str(rule.get("do"))})
        return {"name": self.name, "configured": True, "allow": allow, "block": block, "other": other, "lists": [], "profile": self.profile_id()}

    def _ingested_rows(self, minutes: int):
        return [x for x in recent_live_logs(minutes=minutes, provider=self.name, limit=5000)]

    def analytics(self, hours: int) -> dict[str, Any]:
        if not self.enabled:
            return {"provider": self.name, "configured": False, "error": "Not configured", "analytics_available": False, "timeline": [], "reasons": [], "domains": [], "devices": [], "protocols": [], "countries": []}
        try:
            pid = self.profile_id()
        except Exception as e:
            return {"provider": self.name, "configured": True, "error": str(e), "analytics_available": False, "timeline": [], "reasons": [], "domains": [], "devices": [], "protocols": [], "countries": []}
        rows = self._ingested_rows(hours * 60)
        if not rows:
            return {
                "provider": self.name, "configured": True, "online": True, "analytics_available": False,
                "error": f"Policy API online for profile {pid}. Control D does not expose query analytics through the public API; enable SIEM log streaming to feed live queries into this console.",
                "timeline": [], "reasons": [], "domains": [], "devices": [], "protocols": [], "countries": [],
            }
        buckets = {}
        reason_counts = {}
        domain_counts = {}
        device_counts = {}
        protocol_counts = {}
        for row in rows:
            try:
                dt = datetime.fromisoformat(str(row["timestamp"]).replace("Z", "+00:00"))
            except Exception:
                continue
            dt = dt.astimezone(timezone.utc).replace(minute=0, second=0, microsecond=0)
            key = dt.isoformat().replace("+00:00", "Z")
            b = buckets.setdefault(key, {"time": key, "queries": 0, "blocked": 0, "allowed": 0})
            b["queries"] += 1
            if row.get("action") == "blocked": b["blocked"] += 1
            else: b["allowed"] += 1
            for mapping, keyname in ((reason_counts, row.get("reason")), (domain_counts, row.get("domain")), (device_counts, row.get("device")), (protocol_counts, row.get("protocol"))):
                if keyname: mapping[str(keyname)] = mapping.get(str(keyname), 0) + 1
        def top(d, limit=25):
            return [{"name": k, "value": v} for k, v in sorted(d.items(), key=lambda x: x[1], reverse=True)[:limit]]
        return {
            "provider": self.name, "configured": True, "online": True, "analytics_available": True, "error": None,
            "timeline": [buckets[k] for k in sorted(buckets)],
            "total_queries": sum(x["queries"] for x in buckets.values()),
            "blocked_queries": sum(x["blocked"] for x in buckets.values()),
            "reasons": top(reason_counts), "domains": top(domain_counts), "devices": top(device_counts), "protocols": top(protocol_counts), "countries": [],
        }

    def recent_logs(self, minutes: int = 5, limit: int = 300):
        rows = self._ingested_rows(minutes)[:max(1, min(limit, 5000))]
        return rows, None if rows else "No Control D SIEM log data has been ingested yet"

    def blocked_logs(self, hours: int):
        rows = self._ingested_rows(hours * 60)
        return [r for r in rows if r.get("action") == "blocked"], None if rows else "No Control D SIEM log data has been ingested"

    def add_rule(self, domain: str, action: str):
        return self.set_rule(domain, action)

    def set_rule(self, domain: str, action: str):
        pid = self.profile_id()
        d = _domain(domain)
        # Control D's custom rule model is one action per hostname. Re-issuing the hostname
        # with the desired action updates the state, so no stale opposite rule is retained.
        r = requests.put(
            f"{self.base}/profiles/{quote(pid, safe='')}/rules",
            headers={**self.headers(), "Content-Type": "application/x-www-form-urlencoded"},
            data={"do": 1 if action == "allow" else 0, "status": 1, "hostnames[]": d, "comment": "DNS Control Center"},
            timeout=TIMEOUT,
        )
        body = _json(r)
        return body

    def remove_rule(self, domain: str, action: str):
        pid = self.profile_id()
        d = _domain(domain)
        r = requests.delete(f"{self.base}/profiles/{quote(pid, safe='')}/rules/{quote(d, safe='')}", headers=self.headers(), timeout=TIMEOUT)
        body = _json(r)
        if not r.ok:
            raise RuntimeError(f"Control D rule delete HTTP {r.status_code}: {body}")
        return body

    def is_allowed(self, domain: str):
        d = _domain(domain)
        for rule in self._all_rules():
            hosts = rule.get("hostnames") or rule.get("hostname") or []
            if isinstance(hosts, str):
                hosts = [hosts]
            action = int(rule.get("do", -1)) if str(rule.get("do", "")).isdigit() else rule.get("do")
            if action in (1, "BYPASS") and any(str(h).lower().rstrip(".") == d for h in hosts):
                return bool(rule.get("status", 1))
        return False

class AdGuardDNS(BaseProvider):
    name = "AdGuard DNS"

    def __init__(self, c: Config):
        self.c = c
        self.base = "https://api.adguard-dns.io"

    @property
    def enabled(self):
        return self.c.adguard_dns_enabled and bool(self.c.adguard_dns_api_key and self.c.adguard_dns_server_id)

    def headers(self):
        return {"Authorization": f"ApiKey {self.c.adguard_dns_api_key}", "Accept": "application/json"}

    def server(self):
        """Return the server object; fall back to the list endpoint for older API deployments."""
        url = f"{self.base}/oapi/v1/dns_servers/{self.c.adguard_dns_server_id}"
        r = requests.get(url, headers=self.headers(), timeout=TIMEOUT)
        if r.ok:
            return _json(r)
        # Fallback: the endpoint used by the user's successful credential test returns the server + settings.
        lr = requests.get(f"{self.base}/oapi/v1/dns_servers", headers=self.headers(), timeout=TIMEOUT)
        data = _json(lr)
        for server in data if isinstance(data, list) else data.get("items", []):
            if str(server.get("id")) == str(self.c.adguard_dns_server_id):
                return server
        raise RuntimeError(f"HTTP {r.status_code}: AdGuard DNS server {self.c.adguard_dns_server_id} not found")

    def settings(self):
        server = self.server()
        settings = server.get("settings") if isinstance(server, dict) else None
        if settings is not None:
            return settings
        # Current OpenAPI also exposes this endpoint; keep as a last-resort fallback.
        r = requests.get(f"{self.base}/oapi/v1/dns_servers/{self.c.adguard_dns_server_id}/settings", headers=self.headers(), timeout=TIMEOUT)
        return _json(r)

    def status(self):
        if not self.enabled:
            return {"enabled": False, "configured": False, "name": self.name}
        server = self.server()
        return {
            "enabled": True,
            "configured": True,
            "name": self.name,
            "server_id": self.c.adguard_dns_server_id,
            "server": server.get("name", self.c.adguard_dns_server_id),
            "settings": server.get("settings", {}),
        }

    def policy(self):
        if not self.enabled:
            return {"name": self.name, "allow": [], "block": [], "other": [], "lists": [], "configured": False}
        s = self.settings()
        urs = s.get("user_rules_settings") or {}
        rules = list(urs.get("rules") or [])
        normalized = _normalize_rules(rules)
        lists = []
        fl = s.get("filter_lists_settings") or {}
        for item in fl.get("filter_list", []) or []:
            lists.append({"type": "blocklist", "id": item.get("filter_id", ""), "enabled": bool(item.get("enabled", False))})
        return {"name": self.name, "configured": True, **normalized, "lists": lists, "server_id": self.c.adguard_dns_server_id}

    def blocked_logs(self, hours: int):
        if not self.enabled:
            return [], "Not configured"
        end = int(time.time() * 1000)
        start = end - hours * 3600 * 1000
        r = requests.get(f"{self.base}/oapi/v1/query_log", headers=self.headers(), params=[("time_from_millis", start), ("time_to_millis", end), ("dns_servers", self.c.adguard_dns_server_id), ("statuses", "REQUEST_BLOCKED"), ("limit", 1000)], timeout=TIMEOUT)
        data = _json(r)
        rows = []
        for item in data.get("items", []):
            info = item.get("filtering_info") or {}
            try:
                domain = _domain(item.get("domain", ""))
            except ValueError:
                continue
            rows.append({"provider": self.name, "domain": domain, "timestamp": item.get("time_iso"), "blocked": True, "reason": info.get("filter_rule") or info.get("filter_id") or info.get("filtering_type") or "Blocked", "detail": info})
        return rows, None

    def analytics(self, hours: int) -> dict[str, Any]:
        if not self.enabled:
            return {"provider": self.name, "configured": False, "error": "Not configured", "timeline": [], "reasons": [], "domains": [], "devices": [], "protocols": [], "countries": []}

        end = int(time.time() * 1000)
        start = end - hours * 3600 * 1000
        time_params = {"time_from_millis": start, "time_to_millis": end, "dns_servers": self.c.adguard_dns_server_id}
        ranked_params = {**time_params, "limit": 100}
        endpoints = {
            "time": ("time", time_params),
            "countries": ("countries", ranked_params),
            "domains": ("domains", ranked_params),
            "devices": ("devices", ranked_params),
            "companies": ("companies", ranked_params),
            "categories": ("categories", ranked_params),
        }
        data: dict[str, Any] = {}
        errors: dict[str, str] = {}
        for key, (path, params) in endpoints.items():
            try:
                r = requests.get(f"{self.base}/oapi/v1/stats/{path}", headers=self.headers(), params=params, timeout=TIMEOUT)
                data[key] = _json(r)
            except Exception as exc:
                errors[key] = str(exc)
                data[key] = {"stats": []}

        time_stats = (data.get("time") or {}).get("stats") or []
        timeline = []
        for item in time_stats:
            value = item.get("value") or {}
            ts = item.get("time_millis")
            if ts is None:
                continue
            try:
                iso = datetime.fromtimestamp(int(ts) / 1000, tz=timezone.utc).isoformat().replace("+00:00", "Z")
            except (TypeError, ValueError, OSError):
                continue
            queries_count = int(_num(value.get("queries")))
            blocked_count = int(_num(value.get("blocked")))
            timeline.append({"time": iso, "queries": queries_count, "blocked": blocked_count, "allowed": max(0, queries_count - blocked_count)})
        timeline.sort(key=lambda x: x["time"])

        def named(payload: dict[str, Any], label_keys: tuple[str, ...], limit: int = 25, use_blocked: bool = False):
            rows = []
            for item in (payload.get("stats") or []):
                label = next((item.get(k) for k in label_keys if item.get(k) not in (None, "")), None)
                value = item.get("value") or {}
                if label is None:
                    continue
                count = _num(value.get("blocked" if use_blocked else "queries"))
                rows.append({"name": str(label), "value": int(count)})
            rows.sort(key=lambda x: x["value"], reverse=True)
            return rows[:limit]

        countries = []
        for row in named(data.get("countries", {}), ("country",), 50):
            code = row["name"].upper()
            if len(code) == 2:
                countries.append({"code": code, "value": row["value"], "kind": "response"})

        return {
            "provider": self.name,
            "configured": True,
            "error": None if timeline or not errors else "; ".join(f"{k}: {v}" for k, v in errors.items()),
            "partial_errors": errors,
            "total_queries": int(sum(x["queries"] for x in timeline)),
            "blocked_queries": int(sum(x["blocked"] for x in timeline)),
            "timeline": timeline,
            "reasons": named(data.get("categories", {}), ("category_type", "category"), 25, use_blocked=True),
            "domains": named(data.get("domains", {}), ("domain",)),
            "devices": named(data.get("devices", {}), ("device_id", "device", "name")),
            "protocols": [],
            "countries": countries,
            "companies": named(data.get("companies", {}), ("company_id", "company", "name")),
        }

    def recent_logs(self, minutes: int = 5, limit: int = 300):
        if not self.enabled:
            return [], "Not configured"
        end = int(time.time() * 1000)
        start = end - max(1, minutes) * 60 * 1000
        params = [
            ("time_from_millis", start), ("time_to_millis", end),
            ("dns_servers", self.c.adguard_dns_server_id), ("limit", max(20, min(limit, 1000)))
        ]
        r = requests.get(f"{self.base}/oapi/v1/query_log", headers=self.headers(), params=params, timeout=5)
        data = _json(r)
        items = data.get("items") or data.get("data") or []
        rows = []
        for item in items:
            try:
                domain = _domain(item.get("domain", ""))
            except ValueError:
                continue
            info = item.get("filtering_info") or {}
            filtering_status = str(info.get("filtering_status") or "").upper()
            action = "blocked" if filtering_status in {"REQUEST_BLOCKED", "RESPONSE_BLOCKED"} else "allowed"
            rows.append({
                "provider": self.name, "domain": domain, "timestamp": item.get("time_iso"), "action": action,
                "reason": info.get("filter_rule") or info.get("filter_id") or info.get("filtering_type") or filtering_status or "Allowed",
                "client": item.get("client_ip") or "", "device": item.get("device_id") or "", "protocol": item.get("protocol") or "",
                "country": item.get("client_country") or "", "detail": item,
            })
        return rows, None

    def _set_rules(self, rules: list[str], enabled=True):
        payload = {"user_rules_settings": {"enabled": bool(enabled), "rules": rules}}
        r = requests.put(f"{self.base}/oapi/v1/dns_servers/{self.c.adguard_dns_server_id}/settings", headers={**self.headers(), "Content-Type": "application/json"}, json=payload, timeout=TIMEOUT)
        return _json(r)

    def add_rule(self, domain: str, action: str):
        return self.set_rule(domain, action)

    def set_rule(self, domain: str, action: str):
        d = _domain(domain)
        s = self.settings()
        urs = s.get("user_rules_settings") or {}
        rules = list(urs.get("rules") or [])
        allow_rule, block_rule = f"@@||{d}^", f"||{d}^"
        rules = [x for x in rules if str(x).strip() not in {allow_rule, block_rule}]
        rules.append(allow_rule if action == "allow" else block_rule)
        return self._set_rules(rules, urs.get("enabled", True))

    def remove_rule(self, domain: str, action: str):
        d = _domain(domain)
        s = self.settings()
        urs = s.get("user_rules_settings") or {}
        targets = {f"@@||{d}^", f"||{d}^"}
        rules = [x for x in (urs.get("rules") or []) if x.strip() not in targets]
        return self._set_rules(rules, urs.get("enabled", True))

    def is_allowed(self, domain: str):
        d = _domain(domain)
        rules = (self.settings().get("user_rules_settings") or {}).get("rules") or []
        return f"@@||{d}^" in rules


class AdGuardHome(BaseProvider):
    name = "AdGuard Home"

    def __init__(self, c: Config):
        self.c = c

    @property
    def enabled(self):
        return self.c.adguard_home_enabled and bool(self.c.adguard_home_url)

    def auth(self):
        if self.c.adguard_home_user:
            return (self.c.adguard_home_user, self.c.adguard_home_password)
        return None

    def status(self):
        if not self.enabled:
            return {"enabled": False, "configured": False, "name": self.name}
        r = requests.get(f"{self.c.adguard_home_url}/control/status", auth=self.auth(), timeout=TIMEOUT)
        data = _json(r)
        return {"enabled": True, "configured": True, "name": self.name, "version": data.get("version", "unknown"), "running": data.get("running", True)}

    def filtering_status(self):
        r = requests.get(f"{self.c.adguard_home_url}/control/filtering/status", auth=self.auth(), timeout=TIMEOUT)
        return _json(r)

    def policy(self):
        if not self.enabled:
            return {"name": self.name, "allow": [], "block": [], "other": [], "lists": [], "configured": False}
        s = self.filtering_status()
        normalized = _normalize_rules(list(s.get("user_rules") or []))
        lists = []
        for f in s.get("filters", []) or []:
            lists.append({"type": "blocklist", "id": f.get("id"), "name": f.get("name"), "url": f.get("url"), "enabled": bool(f.get("enabled", False)), "rules_count": f.get("rules_count")})
        for f in s.get("whitelist_filters", []) or []:
            lists.append({"type": "allowlist", "id": f.get("id"), "name": f.get("name"), "url": f.get("url"), "enabled": bool(f.get("enabled", False)), "rules_count": f.get("rules_count")})
        return {"name": self.name, "configured": True, **normalized, "lists": lists, "version": None}

    def blocked_logs(self, hours: int):
        if not self.enabled:
            return [], "Not configured"
        rows = []
        older_than = ""
        cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
        for _ in range(8):
            params = {"older_than": older_than} if older_than else {}
            r = requests.get(f"{self.c.adguard_home_url}/control/querylog", params=params, auth=self.auth(), timeout=TIMEOUT)
            data = _json(r)
            for item in data.get("data", []):
                result = item.get("reason", "")
                blocked = result in {"FilteredBlackList", "FilteredBlockedService", "FilteredSafeBrowsing", "FilteredParental"} or bool(item.get("rule"))
                if not blocked:
                    continue
                host = item.get("question", {}).get("host", "") or item.get("QH", "")
                try:
                    host = _domain(host)
                except ValueError:
                    continue
                ts = item.get("time") or item.get("T")
                if ts:
                    try:
                        if datetime.fromisoformat(str(ts).replace("Z", "+00:00")) < cutoff:
                            continue
                    except ValueError:
                        pass
                rows.append({"provider": self.name, "domain": host, "timestamp": ts, "blocked": True, "reason": item.get("rule") or result or "Blocked", "detail": item})
                if len(rows) >= 1000:
                    return rows, None
            older_than = data.get("oldest", "")
            if not older_than:
                break
        return rows, None

    def analytics(self, hours: int) -> dict[str, Any]:
        if not self.enabled:
            return {"provider": self.name, "configured": False, "error": "Not configured", "timeline": [], "reasons": [], "domains": [], "devices": [], "protocols": [], "countries": []}
        r = requests.get(f"{self.c.adguard_home_url}/control/stats", params={"recent": hours * 3600000}, auth=self.auth(), timeout=TIMEOUT)
        s = _json(r)
        queries = list(s.get("dns_queries") or [])
        blocked = list(s.get("blocked_filtering") or [])
        interval = str(s.get("time_units") or "hours")
        # AGH exposes arrays in chronological order. The API does not return absolute bucket timestamps here,
        # so build relative labels from now, keeping the chart honest about the source granularity.
        now = datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0)
        step = timedelta(hours=1) if interval == "hours" else timedelta(days=1)
        n = max(len(queries), len(blocked))
        timeline = []
        for i in range(n):
            t = now - step * (n - 1 - i)
            qv = int(queries[i] if i < len(queries) else 0)
            bv = int(blocked[i] if i < len(blocked) else 0)
            timeline.append({"time": t.isoformat().replace("+00:00", "Z"), "queries": qv, "blocked": bv, "allowed": max(0, qv - bv)})
        def top_array(key):
            arr=s.get(key) or []
            out=[]
            for item in arr:
                if isinstance(item, dict):
                    name=item.get("domain_or_ip") or item.get("name") or item.get("domain")
                    val=item.get("count") or item.get("queries") or item.get("value")
                    if name is not None and val is not None: out.append({"name":str(name),"value":int(_num(val))})
            out.sort(key=lambda x:x["value"], reverse=True)
            return out[:25]
        return {
            "provider": self.name, "configured": True,
            "total_queries": int(s.get("num_dns_queries") or sum(x["queries"] for x in timeline)),
            "blocked_queries": int(s.get("num_blocked_filtering") or sum(x["blocked"] for x in timeline)),
            "timeline": timeline, "reasons": [],
            "domains": top_array("top_queried_domains"), "blocked_domains": top_array("top_blocked_domains"),
            "devices": top_array("top_clients"), "protocols": [], "countries": [],
        }

    def recent_logs(self, minutes: int = 5, limit: int = 300):
        if not self.enabled:
            return [], "Not configured"
        r = requests.get(
            f"{self.c.adguard_home_url}/control/querylog",
            params={"offset": 0, "limit": max(20, min(limit, 1000))},
            auth=self.auth(), timeout=5
        )
        data = _json(r)
        rows = []
        cutoff = datetime.now(timezone.utc) - timedelta(minutes=max(1, minutes))
        for item in data.get("data", []) or []:
            ts = item.get("time")
            try:
                dt = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
                if dt < cutoff:
                    continue
            except Exception:
                pass
            question = item.get("question") or {}
            domain = question.get("host") or ""
            try:
                domain = _domain(domain)
            except ValueError:
                continue
            reason = str(item.get("reason") or "")
            blocked = reason.lower().startswith("filtered") or "blocked" in reason.lower() or bool(item.get("filterId"))
            rows.append({
                "provider": self.name, "domain": domain, "timestamp": ts, "action": "blocked" if blocked else "allowed",
                "reason": item.get("rule") or reason or ("Blocked" if blocked else "Allowed"), "client": item.get("client") or "",
                "device": item.get("client") or "", "protocol": "", "country": "", "detail": item,
            })
        return rows[:max(1, min(limit, 1000))], None

    def _set_rules(self, rules: list[str]):
        r = requests.post(f"{self.c.adguard_home_url}/control/filtering/set_rules", json={"rules": rules}, auth=self.auth(), timeout=TIMEOUT)
        return _json(r)

    def add_rule(self, domain: str, action: str):
        return self.set_rule(domain, action)

    def set_rule(self, domain: str, action: str):
        d = _domain(domain)
        rules = list(self.filtering_status().get("user_rules") or [])
        allow_rule, block_rule = f"@@||{d}^", f"||{d}^"
        rules = [x for x in rules if str(x).strip() not in {allow_rule, block_rule}]
        rules.append(allow_rule if action == "allow" else block_rule)
        return self._set_rules(rules)

    def remove_rule(self, domain: str, action: str):
        d = _domain(domain)
        rules = list(self.filtering_status().get("user_rules") or [])
        targets = {f"@@||{d}^", f"||{d}^"}
        return self._set_rules([x for x in rules if x.strip() not in targets])

    def is_allowed(self, domain: str):
        d = _domain(domain)
        return f"@@||{d}^" in (self.filtering_status().get("user_rules") or [])


class ProviderManager:
    def __init__(self, c: Config):
        self.config = c
        self.providers = [NextDNS(c), ControlD(c), AdGuardDNS(c), AdGuardHome(c)]
        self.cache = {"at": 0.0, "payload": None}
        self._live_lock = threading.Lock()
        self._live_refresh_at = 0.0
        self._live_refresh_error: dict[str, str] = {}
        self._live_thread_started = False

    def start_live_worker(self):
        if self._live_thread_started:
            return
        self._live_thread_started = True
        def loop():
            while True:
                try:
                    self.refresh_live_logs(minutes=2, limit=700, wait=False)
                except Exception:
                    pass
                time.sleep(max(1, int(self.config.live_poll_seconds)))
        threading.Thread(target=loop, name="dns-live-poller", daemon=True).start()

    def status(self):
        out = []
        with ThreadPoolExecutor(max_workers=len(self.providers)) as ex:
            jobs = {ex.submit(p.status): p for p in self.providers}
            for f in as_completed(jobs):
                p = jobs[f]
                try:
                    out.append(f.result())
                except Exception as e:
                    out.append({"enabled": True, "configured": True, "name": p.name, "error": str(e)})
        order = {p.name: i for i, p in enumerate(self.providers)}
        return sorted(out, key=lambda x: order.get(x.get("name", ""), 999))

    def blocked(self, hours: int):
        now = time.time()
        if self.cache["payload"] is not None and now - self.cache["at"] < 20:
            return self.cache["payload"]
        all_rows = []
        messages = {}
        with ThreadPoolExecutor(max_workers=len(self.providers)) as ex:
            jobs = {ex.submit(p.blocked_logs, hours): p for p in self.providers}
            for f in as_completed(jobs):
                p = jobs[f]
                try:
                    rows, msg = f.result()
                    all_rows.extend(rows)
                    if msg:
                        messages[p.name] = msg
                except Exception as e:
                    messages[p.name] = str(e)
        grouped = {}
        for row in all_rows:
            d = row["domain"]
            g = grouped.setdefault(d, {"domain": d, "providers": {}, "last_seen": row.get("timestamp"), "reasons": []})
            g["providers"][row["provider"]] = {"blocked": True, "timestamp": row.get("timestamp"), "reason": row.get("reason", "")}
            if row.get("timestamp") and (not g["last_seen"] or row["timestamp"] > g["last_seen"]):
                g["last_seen"] = row["timestamp"]
            if row.get("reason") and row["reason"] not in g["reasons"]:
                g["reasons"].append(row["reason"])
        ex = {x["domain"] for x in list_exceptions()}
        result = []
        for d, g in grouped.items():
            g["blocked_by"] = list(g["providers"].keys())
            g["blocked_count"] = len(g["blocked_by"])
            g["exception"] = d in ex
            result.append(g)
        result.sort(key=lambda x: (-x["blocked_count"], x.get("last_seen") or ""))
        payload = {"domains": result, "provider_messages": messages, "generated_at": datetime.now(timezone.utc).isoformat()}
        self.cache = {"at": now, "payload": payload}
        return payload

    def analytics(self, hours: int = 24) -> dict[str, Any]:
        results=[]
        with ThreadPoolExecutor(max_workers=len(self.providers)) as ex:
            jobs={ex.submit(p.analytics, hours): p for p in self.providers}
            for f in as_completed(jobs):
                p=jobs[f]
                try:
                    x=f.result()
                except Exception as e:
                    x={"provider":p.name,"configured":bool(getattr(p, "enabled", True)),"error":str(e),"timeline":[],"reasons":[],"domains":[],"devices":[],"protocols":[],"countries":[]}
                results.append(x)
        order={p.name:i for i,p in enumerate(self.providers)}
        results.sort(key=lambda x:order.get(x.get("provider",""),999))
        # One common hourly grid for the combined chart prevents false zig-zags caused by
        # provider-native bucket sizes (for example 15m vs 1h). Individual provider charts
        # retain their native granularity.
        combined = _common_combined_timeline(results, 3600)
        return {"hours":hours,"providers":results,"combined_timeline":combined,"combined_bucket_seconds":3600,"generated_at":datetime.now(timezone.utc).isoformat()}

    def policies(self):
        out = []
        with ThreadPoolExecutor(max_workers=len(self.providers)) as ex:
            jobs = {ex.submit(p.policy): p for p in self.providers}
            for f in as_completed(jobs):
                p = jobs[f]
                try:
                    x = f.result()
                    x["error"] = None
                except Exception as e:
                    x = {"name": p.name, "allow": [], "block": [], "other": [], "lists": [], "configured": True, "error": str(e)}
                out.append(x)
        order = {p.name: i for i, p in enumerate(self.providers)}
        return sorted(out, key=lambda x: order.get(x.get("name", ""), 999))

    def refresh_live_logs(self, minutes: int = 2, limit: int = 700, wait: bool = True):
        minutes = max(1, min(int(minutes), 15))
        limit = max(50, min(int(limit), 1200))
        direct = []
        messages = {}
        started = time.time()
        # Provider adapters are deliberately called concurrently. The dashboard never waits
        # for one slow resolver before collecting the other three.
        with ThreadPoolExecutor(max_workers=len(self.providers)) as ex:
            jobs = {ex.submit(p.recent_logs, minutes, min(limit, 700)): p for p in self.providers}
            for f in as_completed(jobs):
                p = jobs[f]
                try:
                    r, msg = f.result()
                    direct.extend(r or [])
                    if msg: messages[p.name] = msg
                except Exception as e:
                    messages[p.name] = str(e)
        accepted = ingest_live_logs("_bulk", [])
        # Store each provider separately so filters can query SQLite without re-hitting APIs.
        stored_count = 0
        if direct:
            by_provider: dict[str, list[dict[str, Any]]] = {}
            for row in direct:
                by_provider.setdefault(str(row.get("provider") or "Unknown"), []).append(row)
            for pname, rows in by_provider.items():
                stored_count += ingest_live_logs(pname, rows)
        with self._live_lock:
            self._live_refresh_at = time.time()
            self._live_refresh_error = messages
        return {"accepted": stored_count, "messages": messages, "duration_ms": int((time.time()-started)*1000)}

    def live_logs(self, minutes: int = 5, limit: int = 500, provider: str = "all", status: str = "all", search: str = "", fresh: bool = False):
        minutes = max(1, min(int(minutes), 60))
        limit = max(1, min(int(limit), 2000))
        if fresh:
            self.refresh_live_logs(minutes=min(minutes, 2), limit=min(limit, 700), wait=True)
        # The normal path is intentionally just a local SQLite read. This makes the live UI fast
        # even if a remote provider is slow or temporarily unavailable.
        messages = dict(self._live_refresh_error)
        rows = recent_live_logs(minutes=minutes, limit=limit, provider=provider, status=status, search=search or None)
        with self._live_lock:
            refreshed = self._live_refresh_at
        return {"rows": rows, "messages": messages, "refreshed_at": datetime.fromtimestamp(refreshed, timezone.utc).isoformat() if refreshed else None, "generated_at": datetime.now(timezone.utc).isoformat()}

    def provider_exception_state(self, domain: str):
        out = {}
        for p in self.providers:
            try:
                out[p.name] = {"allowed": bool(p.is_allowed(domain)), "error": None}
            except Exception as e:
                out[p.name] = {"allowed": None, "error": str(e)}
        return out

    def add_rule(self, domain: str, action: str, scope: str = "all"):
        results = []
        targets = self.providers if scope == "all" else [p for p in self.providers if p.name.lower().replace(" ", "_") == scope.lower().replace(" ", "_")]
        if not targets:
            raise ValueError(f"Unknown provider: {scope}")
        for p in targets:
            try:
                p.set_rule(domain, action)
                results.append({"provider": p.name, "ok": True})
            except Exception as e:
                results.append({"provider": p.name, "ok": False, "error": str(e)})
        self.cache = {"at": 0.0, "payload": None}
        return results

    def remove_rule(self, domain: str, action: str, scope: str = "all"):
        results = []
        targets = self.providers if scope == "all" else [p for p in self.providers if p.name.lower().replace(" ", "_") == scope.lower().replace(" ", "_")]
        if not targets:
            raise ValueError(f"Unknown provider: {scope}")
        for p in targets:
            try:
                p.remove_rule(domain, action)
                results.append({"provider": p.name, "ok": True})
            except Exception as e:
                results.append({"provider": p.name, "ok": False, "error": str(e)})
        self.cache = {"at": 0.0, "payload": None}
        return results
