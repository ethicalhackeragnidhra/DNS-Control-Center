import sqlite3
import hashlib
from pathlib import Path
from datetime import datetime, timezone

DB_PATH = Path("/app/data/dns-control-center.db")


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def connect():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with connect() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS exceptions (
                domain TEXT PRIMARY KEY,
                note TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT NOT NULL,
                action TEXT NOT NULL,
                provider TEXT NOT NULL,
                success INTEGER NOT NULL,
                detail TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_audit_domain ON audit_log(domain);
            CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_log(created_at);
            CREATE TABLE IF NOT EXISTS live_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                provider TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                domain TEXT NOT NULL,
                action TEXT NOT NULL DEFAULT 'allowed',
                reason TEXT NOT NULL DEFAULT '',
                client TEXT NOT NULL DEFAULT '',
                device TEXT NOT NULL DEFAULT '',
                protocol TEXT NOT NULL DEFAULT '',
                country TEXT NOT NULL DEFAULT '',
                detail TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_live_logs_time ON live_logs(timestamp DESC);
            CREATE INDEX IF NOT EXISTS idx_live_logs_provider ON live_logs(provider, timestamp DESC);
            """
        )
        columns = {row[1] for row in conn.execute("PRAGMA table_info(live_logs)").fetchall()}
        if "event_key" not in columns:
            conn.execute("ALTER TABLE live_logs ADD COLUMN event_key TEXT")
        rows = conn.execute("SELECT id,provider,timestamp,domain,action,reason,client,device,protocol,country FROM live_logs WHERE event_key IS NULL OR event_key = ''").fetchall()
        for row in rows:
            raw_key = "|".join(str(row[i] or "") for i in range(1, 10))
            key = hashlib.sha256(raw_key.encode("utf-8", "ignore")).hexdigest()
            conn.execute("UPDATE live_logs SET event_key=? WHERE id=?", (key, row[0]))
        conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_live_logs_event ON live_logs(event_key)")


def list_exceptions():
    with connect() as conn:
        return [dict(x) for x in conn.execute("SELECT * FROM exceptions ORDER BY domain").fetchall()]


def get_exception(domain: str):
    with connect() as conn:
        row = conn.execute("SELECT * FROM exceptions WHERE domain = ?", (domain,)).fetchone()
        return dict(row) if row else None


def upsert_exception(domain: str, note: str = ""):
    ts = now_iso()
    with connect() as conn:
        conn.execute(
            """INSERT INTO exceptions(domain,note,created_at,updated_at) VALUES(?,?,?,?)
               ON CONFLICT(domain) DO UPDATE SET note=excluded.note, updated_at=excluded.updated_at""",
            (domain, note, ts, ts),
        )


def delete_exception(domain: str):
    with connect() as conn:
        conn.execute("DELETE FROM exceptions WHERE domain = ?", (domain,))


def audit(domain: str, action: str, provider: str, success: bool, detail: str = ""):
    with connect() as conn:
        conn.execute(
            "INSERT INTO audit_log(domain,action,provider,success,detail,created_at) VALUES(?,?,?,?,?,?)",
            (domain, action, provider, int(success), detail[:2000], now_iso()),
        )


def audit_for_domain(domain: str, limit: int = 30):
    with connect() as conn:
        return [
            dict(x)
            for x in conn.execute(
                "SELECT * FROM audit_log WHERE domain=? ORDER BY id DESC LIMIT ?", (domain, limit)
            ).fetchall()
        ]


def ingest_live_logs(provider: str, rows: list[dict], max_rows: int = 10000):
    if not rows:
        return 0
    inserted = 0
    with connect() as conn:
        values = []
        for row in rows:
            domain = str(row.get("domain") or "")
            if not domain:
                continue
            timestamp = str(row.get("timestamp") or now_iso())
            action = str(row.get("action") or "allowed")
            reason = str(row.get("reason") or "")
            client = str(row.get("client") or "")
            device = str(row.get("device") or "")
            protocol = str(row.get("protocol") or "")
            country = str(row.get("country") or "")
            # Stable event identity prevents the fast background poller from duplicating the
            # same provider query on every refresh while retaining distinct clients/devices.
            raw_key = "|".join((provider, timestamp, domain, action, reason, client, device, protocol, country))
            event_key = hashlib.sha256(raw_key.encode("utf-8", "ignore")).hexdigest()
            values.append((
                provider, timestamp, domain, action, reason, client, device, protocol, country,
                str(row.get("detail") or "")[:10000], now_iso(), event_key
            ))
        if values:
            conn.executemany(
                """INSERT OR IGNORE INTO live_logs
                   (provider,timestamp,domain,action,reason,client,device,protocol,country,detail,created_at,event_key)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""", values
            )
            inserted = conn.total_changes
        conn.execute(
            "DELETE FROM live_logs WHERE id NOT IN (SELECT id FROM live_logs ORDER BY id DESC LIMIT ?)",
            (max_rows,),
        )
    return inserted


def recent_live_logs(minutes: int = 60, limit: int = 1000, provider: str | None = None, status: str | None = None, search: str | None = None):
    minutes = max(1, min(int(minutes), 1440))
    limit = max(1, min(int(limit), 5000))
    cutoff = datetime.now(timezone.utc).timestamp() - minutes * 60
    clauses=[]; params=[]
    if provider and provider.lower() != "all":
        clauses.append("provider = ?"); params.append(provider)
    if status and status.lower() != "all":
        clauses.append("action = ?"); params.append(status.lower())
    if search:
        clauses.append("domain LIKE ?"); params.append(f"%{search.strip()}%")
    where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
    with connect() as conn:
        raw = [dict(x) for x in conn.execute(
            f"SELECT * FROM live_logs{where} ORDER BY id DESC LIMIT ?",
            (*params, min(5000, max(limit * 6, limit))),
        ).fetchall()]
    out=[]
    for row in raw:
        ts=row.get("timestamp")
        try:
            dt=datetime.fromisoformat(str(ts).replace("Z","+00:00"))
            if dt.timestamp() < cutoff:
                continue
        except Exception:
            # Keep a row with an unparsable timestamp visible rather than silently dropping it.
            pass
        out.append(row)
        if len(out)>=limit:
            break
    return out

