from __future__ import annotations

from urllib.request import getproxies, proxy_bypass


SYSTEM_PROXY = "system://"


def is_system_proxy(value: object) -> bool:
    return value == SYSTEM_PROXY


def system_proxies() -> dict[str, str]:
    """Return static proxies exposed by the OS and standard proxy variables."""
    result: dict[str, str] = {}
    for key, raw_value in getproxies().items():
        scheme = str(key).strip().lower()
        value = str(raw_value).strip()
        if scheme not in {"http", "https", "all"} or not value:
            continue
        if "://" not in value:
            value = f"http://{value}"
        result[scheme] = value
    return result


def system_proxy_url(host: str = "") -> str:
    """Select a static system proxy suitable for an IMAP TCP tunnel."""
    if host and proxy_bypass(host):
        return ""
    proxies = system_proxies()
    return proxies.get("https") or proxies.get("all") or proxies.get("http") or ""
