import os
from dataclasses import dataclass


def flag(name: str, default: bool = True) -> bool:
    return os.getenv(name, str(default)).strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Config:
    app_name: str = os.getenv("APP_NAME", "DNS Control Center")
    admin_username: str = os.getenv("ADMIN_USERNAME", "admin")
    admin_password: str = os.getenv("ADMIN_PASSWORD", "change-me-now")
    flask_secret_key: str = os.getenv("FLASK_SECRET_KEY", "change-me")
    log_window_hours: int = int(os.getenv("LOG_WINDOW_HOURS", "24"))
    cache_ttl_seconds: int = int(os.getenv("CACHE_TTL_SECONDS", "20"))
    live_poll_seconds: int = max(1, int(os.getenv("LIVE_POLL_SECONDS", "2")))

    nextdns_enabled: bool = flag("NEXTDNS_ENABLED")
    nextdns_api_key: str = os.getenv("NEXTDNS_API_KEY", "")
    nextdns_profile_id: str = os.getenv("NEXTDNS_PROFILE_ID", "")

    controld_enabled: bool = flag("CONTROLD_ENABLED")
    controld_api_token: str = os.getenv("CONTROLD_API_TOKEN", "")
    controld_profile_id: str = os.getenv("CONTROLD_PROFILE_ID", "")
    controld_profile_name: str = os.getenv("CONTROLD_PROFILE_NAME", "")
    controld_analytics_base_url: str = os.getenv("CONTROLD_ANALYTICS_BASE_URL", "").rstrip("/")
    controld_analytics_endpoint_id: str = os.getenv("CONTROLD_ANALYTICS_ENDPOINT_ID", "")
    controld_force_org_id: str = os.getenv("CONTROLD_FORCE_ORG_ID", "")
    controld_log_ingest_secret: str = os.getenv("CONTROLD_LOG_INGEST_SECRET", "")

    adguard_dns_enabled: bool = flag("ADGUARD_DNS_ENABLED")
    adguard_dns_api_key: str = os.getenv("ADGUARD_DNS_API_KEY", "")
    adguard_dns_server_id: str = os.getenv("ADGUARD_DNS_SERVER_ID", "")

    adguard_home_enabled: bool = flag("ADGUARD_HOME_ENABLED")
    adguard_home_url: str = os.getenv("ADGUARD_HOME_URL", "http://adguardhome:3000").rstrip("/")
    adguard_home_user: str = os.getenv("ADGUARD_HOME_USER", "")
    adguard_home_password: str = os.getenv("ADGUARD_HOME_PASSWORD", "")
