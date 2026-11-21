import socket, random, json, os, urllib.request, urllib.parse, base64, time
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization

SOURCES = [
    "https://raw.githubusercontent.com/ebrasha/free-v2ray-public-list/refs/heads/main/V2Ray-Config-By-EbraSha.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-Config/main/Sub1.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-Config/main/Sub2.txt",
    "https://raw.githubusercontent.com/yebekhe/TVC/main/subscriptions/xray/normal/vless",
    "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/main/Protocols/vless.txt",
    "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/sub/sub_merge.txt"
]

COUNTRY_NAMES = {
    "DE": "🇩🇪 Германия",
    "NL": "🇳🇱 Нидерланды",
    "FI": "🇫🇮 Финляндия",
    "SE": "🇸🇪 Швеция",
    "PL": "🇵🇱 Польша",
    "GB": "🇬🇧 Великобритания",
    "US": "🇺🇸 США",
    "FR": "🇫🇷 Франция",
    "CH": "🇨🇭 Швейцария",
    "AT": "🇦🇹 Австрия",
    "CZ": "🇨🇿 Чехия",
    "LV": "🇱🇻 Латвия",
    "EE": "🇪🇪 Эстония",
    "LT": "🇱🇹 Литва",
    "KZ": "🇰🇿 Казахстан",
    "TR": "🇹🇷 Турция",
    "NO": "🇳🇴 Норвегия",
    "DK": "🇩🇰 Дания",
    "CA": "🇨🇦 Канада",
    "SG": "🇸🇬 Сингапур",
    "JP": "🇯🇵 Япония"
}

SUBNETS = ["162.159.192.", "162.159.193.", "162.159.195.", "188.114.96.", "188.114.97."]
PORTS = [854, 859, 864, 894, 908, 2408, 1701, 4500]
WG_HANDSHAKE = bytes.fromhex("01000000" + "00" * 144)
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"

def fetch_lines(url):
    try:
        req = urllib.request.Request(url, headers={"User-Agent": UA})
        with urllib.request.urlopen(req, timeout=12) as resp:
            raw = resp.read().decode("utf-8", errors="ignore").strip()
        if "://" not in raw:
            pad = len(raw) % 4
            if pad:
                raw += "=" * (4 - pad)
            raw = base64.b64decode(raw).decode("utf-8", errors="ignore")
        return [line.strip() for line in raw.splitlines() if line.strip()]
    except Exception:
        return []

def parse_vless_reality(uri):
    if not uri.startswith("vless://") or "security=reality" not in uri:
        return None
    try:
        base_uri = uri.split("#", 1)[0]
        parsed = urllib.parse.urlsplit(base_uri)
        host = parsed.hostname
        port = parsed.port or 443
        if not host or host in ("127.0.0.1", "0.0.0.0", "localhost"):
            return None
        return (host, port, base_uri)
    except Exception:
        return None

def check_tcp(item):
    host, port, base_uri = item
    t0 = time.monotonic()
    try:
        with socket.create_connection((host, port), timeout=1.5):
            ms = int((time.monotonic() - t0) * 1000)
            return (ms, host, port, base_uri)
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
        with urllib.request.urlopen(req, timeout=12) as resp:
            results = json.loads(resp.read().decode())
        for r in results:
            if r.get("status") == "success":
                code = r.get("countryCode", "")
                mapping[r["query"]] = COUNTRY_NAMES.get(code, f"🌍 Европа ({code})")
    except Exception:
        pass
    return mapping

def build_vless_subscriptions():
    all_lines = []
    with ThreadPoolExecutor(max_workers=6) as ex:
        for lines in ex.map(fetch_lines, SOURCES):
            all_lines.extend(lines)

    seen = set()
    candidates = []
    for line in all_lines:
        parsed = parse_vless_reality(line)
        if parsed:
            key = (parsed[0], parsed[1])
            if key not in seen:
                seen.add(key)
                candidates.append(parsed)

    random.shuffle(candidates)
    candidates = candidates[:300]

    with ThreadPoolExecutor(max_workers=60) as ex:
        alive = list(filter(None, ex.map(check_tcp, candidates)))

    alive.sort(key=lambda x: x[0])
    top_nodes = alive[:50]
    geo = resolve_countries([x[1] for x in top_nodes])

    by_country = {}
    for ms, host, port, base_uri in top_nodes:
        country = geo.get(host, "🇪🇺 Европа")
        by_country.setdefault(country, []).append((ms, base_uri))

    free_links = []
    pro_links = []
    countries_json = {}

    for country, items in by_country.items():
        countries_json[country] = []
        for idx, (ms, base_uri) in enumerate(items[:4], start=1):
            label = f"{country} #{idx} ({ms}ms) • The Last VPN"
            full_uri = f"{base_uri}#{urllib.parse.quote(label)}"
            pro_links.append(full_uri)
            if idx == 1 and len(free_links) < 6:
                free_links.append(full_uri)
            countries_json[country].append({"uri": full_uri, "latency": ms})

    os.makedirs("sub", exist_ok=True)
    with open("sub/free", "w", encoding="utf-8") as f:
        f.write(base64.b64encode("\n".join(free_links).encode("utf-8")).decode("ascii"))
    with open("sub/pro", "w", encoding="utf-8") as f:
        f.write(base64.b64encode("\n".join(pro_links).encode("utf-8")).decode("ascii"))
    with open("nodes.json", "w", encoding="utf-8") as f:
        json.dump({"updated": int(time.time()), "countries": countries_json}, f, ensure_ascii=False, indent=2)

    print(f"VLESS Reality ready: {len(free_links)} free, {len(pro_links)} pro across {len(by_country)} countries")

def update_warp_worker():
    base_url = os.environ.get("WORKER_URL", "").rstrip("/")
    secret = os.environ.get("ADMIN_SECRET", "")
    if not base_url or not secret:
        return
    try:
        candidates = [(f"{sub}{random.randint(1, 254)}", random.choice(PORTS)) for sub in SUBNETS for _ in range(40)]
        unique_ips = [f"{ip}:{port}" for ip, port in candidates[:80]]

        priv = x25519.X25519PrivateKey.generate()
        priv_b64 = base64.b64encode(priv.private_bytes(
            serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()
        )).decode()
        pub_b64 = base64.b64encode(priv.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )).decode()

        payload = json.dumps({
            "key": pub_b64,
            "install_id": "",
            "fcm_token": "",
            "tos": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z"),
            "model": "Android",
            "serial_number": "",
            "locale": "en_US"
        }).encode("utf-8")

        req = urllib.request.Request(
            "https://api.cloudflareclient.com/v0a2158/reg",
            data=payload,
            headers={
                "Content-Type": "application/json; charset=UTF-8",
                "User-Agent": "okhttp/3.12.1",
                "CF-Client-Version": "a-6.11-2223"
            },
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=12) as resp:
            data = json.loads(resp.read().decode())

        cid = base64.b64decode(data["config"]["client_id"])
        creds = {
            "privateKey": priv_b64,
            "peerPublicKey": data["config"]["peers"][0]["public_key"],
            "v4": data["config"]["interface"]["addresses"]["v4"],
            "v6": data["config"]["interface"]["addresses"]["v6"],
            "reserved": [cid[0], cid[1], cid[2]]
        }

        for body in ({"type": "raw_ips", "ips": unique_ips}, {"type": "warp_creds", "creds": creds}):
            r = urllib.request.Request(
                base_url + "/admin/update",
                data=json.dumps(body).encode("utf-8"),
                headers={"Content-Type": "application/json", "Authorization": f"Bearer {secret}", "User-Agent": UA},
                method="POST"
            )
            urllib.request.urlopen(r, timeout=12).read()
        print("WARP pool synced!")
    except Exception as e:
        print("WARP sync skipped:", e)

if __name__ == "__main__":
    build_vless_subscriptions()
    update_warp_worker()
