import urllib.request
import urllib.parse
import html
import re
import socket
import base64
import json
import os
import time
from concurrent.futures import ThreadPoolExecutor

TG_CHANNELS = [
    "outlineOpenKey",
    "vlesskeys",
    "shadowsockskeys",
    "vpn_youtube_obhod",
    "obhod_belih_spiskov_vpn"
]

COUNTRY_NAMES = {
    "DE": "🇩🇪 Германия", "NL": "🇳🇱 Нидерланды", "FI": "🇫🇮 Финляндия",
    "SE": "🇸🇪 Швеция", "PL": "🇵🇱 Польша", "GB": "🇬🇧 Великобритания",
    "US": "🇺🇸 США", "FR": "🇫🇷 Франция", "CH": "🇨🇭 Швейцария",
    "AT": "🇦🇹 Австрия", "CZ": "🇨🇿 Чехия", "LV": "🇱🇻 Латвия",
    "EE": "🇪🇪 Эстония", "LT": "🇱🇹 Литва", "KZ": "🇰🇿 Казахстан",
    "TR": "🇹🇷 Турция", "NO": "🇳🇴 Норвегия", "DK": "🇩🇰 Дания",
    "CA": "🇨🇦 Канада", "SG": "🇸🇬 Сингапур", "JP": "🇯🇵 Япония",
    "RU": "🇷🇺 Россия"
}

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
URI_PATTERN = re.compile(r'(?:vless|hy2|hysteria2|trojan|ss)://[^\s<>"\'`]+', re.IGNORECASE)

def fetch_channel_keys(channel):
    url = f"https://t.me/s/{channel}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": UA})
        with urllib.request.urlopen(req, timeout=12) as resp:
            page = resp.read().decode("utf-8", errors="ignore")
    except Exception as e:
        print(f"Skip @{channel}: {e}")
        return []

    cleaned = re.sub(r'<br\s*/?>', '\n', page, flags=re.IGNORECASE)
    cleaned = re.sub(r'<[^>]+>', ' ', cleaned)
    cleaned = html.unescape(cleaned)

    found = URI_PATTERN.findall(cleaned)
    return found[-40:]

def parse_endpoint(uri):
    base_uri = uri.split("#", 1)[0].strip().rstrip(".,;)")
    try:
        p = urllib.parse.urlsplit(base_uri)
        proto = p.scheme.lower()
        host = p.hostname
        port = p.port

        if proto == "ss" and not host and p.netloc:
            raw = p.netloc
            raw += "=" * (-len(raw) % 4)
            decoded = base64.urlsafe_b64decode(raw).decode("utf-8", errors="ignore")
            if "@" in decoded:
                hp = decoded.split("@", 1)[1]
                host, port_s = hp.rsplit(":", 1)
                port = int(port_s)

        if not host or not port or host in ("127.0.0.1", "0.0.0.0", "localhost"):
            return None
        return (proto, host, int(port), base_uri)
    except Exception:
        return None

def check_tcp(item):
    proto, host, port, base_uri = item
    if proto in ("hy2", "hysteria2"):
        return (85, proto, host, port, base_uri)
    t0 = time.monotonic()
    try:
        with socket.create_connection((host, port), timeout=1.5):
            ms = int((time.monotonic() - t0) * 1000)
            return (ms, proto, host, port, base_uri)
    except Exception:
        return None

def resolve_countries(hosts):
    mapping = {}
    unique_hosts = list(set(hosts))[:90]
    if not unique_hosts:
        return mapping
    try:
        req = urllib.request.Request(
            "http://ip-api.com/batch?fields=query,countryCode,status",
            data=json.dumps(unique_hosts).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            for r in json.loads(resp.read().decode()):
                if r.get("status") == "success":
                    code = r.get("countryCode", "")
                    mapping[r["query"]] = COUNTRY_NAMES.get(code, f"🌍 Европа ({code})")
    except Exception:
        pass
    return mapping

def main():
    raw_uris = []
    with ThreadPoolExecutor(max_workers=5) as ex:
        for keys in ex.map(fetch_channel_keys, TG_CHANNELS):
            raw_uris.extend(keys)

    seen = set()
    candidates = []
    for u in reversed(raw_uris):
        parsed = parse_endpoint(u)
        if not parsed:
            continue
        key = (parsed[1], parsed[2], parsed[3][:60])
        if key not in seen:
            seen.add(key)
            candidates.append(parsed)

    print(f"Fresh keys extracted from Telegram: {len(candidates)}")
    with ThreadPoolExecutor(max_workers=50) as ex:
        alive = list(filter(None, ex.map(check_tcp, candidates[:150])))

    alive.sort(key=lambda x: x[0])
    print(f"Alive keys ready for Happ: {len(alive)}")

    if not alive:
        print("No alive keys in this run.")
        return

    geo = resolve_countries([x[2] for x in alive[:60]])
    by_country = {}
    for ms, proto, host, port, base_uri in alive[:60]:
        country = geo.get(host, "🇪🇺 Европа")
        by_country.setdefault(country, []).append((ms, proto.upper(), base_uri))

    free_links = []
    pro_links = []
    countries_json = {}

    for country, items in by_country.items():
        countries_json[country] = []
        for idx, (ms, proto_tag, base_uri) in enumerate(items[:4], start=1):
            label = f"{country} #{idx} [{proto_tag}] ({ms}ms) • The Last VPN"
            full_uri = f"{base_uri}#{urllib.parse.quote(label)}"
            pro_links.append(full_uri)
            if idx <= 2 and len(free_links) < 16:
                free_links.append(full_uri)
            countries_json[country].append({"uri": full_uri, "latency": ms})

    os.makedirs("sub", exist_ok=True)
    with open("sub/free", "w", encoding="utf-8") as f:
        f.write(base64.b64encode("\n".join(free_links).encode("utf-8")).decode("ascii"))
    with open("sub/pro", "w", encoding="utf-8") as f:
        f.write(base64.b64encode("\n".join(pro_links).encode("utf-8")).decode("ascii"))
    with open("nodes.json", "w", encoding="utf-8") as f:
        json.dump({"updated": int(time.time()), "countries": countries_json}, f, ensure_ascii=False, indent=2)

if __name__ == "__main__":
    main()
