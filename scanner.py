import socket, random, json, os, urllib.request, urllib.parse, base64, time, subprocess, struct
from concurrent.futures import ThreadPoolExecutor

SOURCES = [
    "https://raw.githubusercontent.com/ebrasha/free-v2ray-public-list/refs/heads/main/V2Ray-Config-By-EbraSha.txt",
    "https://raw.githubusercontent.com/yebekhe/TVC/main/subscriptions/xray/normal/vless",
    "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/main/Protocols/vless.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-Config/main/Sub1.txt",
    "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/sub/sub_merge.txt"
]

COUNTRY_NAMES = {
    "DE": "🇩🇪 Германия", "NL": "🇳🇱 Нидерланды", "FI": "🇫🇮 Финляндия",
    "SE": "🇸🇪 Швеция", "PL": "🇵🇱 Польша", "GB": "🇬🇧 Великобритания",
    "US": "🇺🇸 США", "FR": "🇫🇷 Франция", "CH": "🇨🇭 Швейцария",
    "AT": "🇦🇹 Австрия", "CZ": "🇨🇿 Чехия", "LV": "🇱🇻 Латвия",
    "EE": "🇪🇪 Эстония", "LT": "🇱🇹 Литва", "KZ": "🇰🇿 Казахстан",
    "TR": "🇹🇷 Турция", "NO": "🇳🇴 Норвегия", "DK": "🇩🇰 Дания",
    "CA": "🇨🇦 Канада", "SG": "🇸🇬 Сингапур", "JP": "🇯🇵 Япония"
}

VALID_FPS = {"chrome", "firefox", "safari", "ios", "android", "edge", "random", "randomized"}
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"

def fetch_lines(url):
    try:
        req = urllib.request.Request(url, headers={"User-Agent": UA})
        with urllib.request.urlopen(req, timeout=10) as resp:
            raw = resp.read().decode("utf-8", errors="ignore").strip()
        if "://" not in raw:
            raw += "=" * (-len(raw) % 4)
            raw = base64.b64decode(raw).decode("utf-8", errors="ignore")
        return [line.strip() for line in raw.splitlines() if line.strip()]
    except Exception:
        return []

def is_valid_pbk(pbk):
    try:
        return len(base64.urlsafe_b64decode(pbk + "=" * (-len(pbk) % 4))) == 32
    except Exception:
        return False

def is_valid_sid(sid):
    return len(sid) <= 16 and len(sid) % 2 == 0 and all(c in "0123456789abcdefABCDEF" for c in sid)

def is_valid_uuid(u):
    parts = u.split("-")
    return len(u) == 36 and [len(x) for x in parts] == [8, 4, 4, 4, 12] and all(c in "0123456789abcdefABCDEF-" for c in u)

def parse_vless_reality(uri):
    if not uri.startswith("vless://") or "security=reality" not in uri:
        return None
    try:
        base_uri = uri.split("#", 1)[0].strip()
        p = urllib.parse.urlsplit(base_uri)
        uuid = urllib.parse.unquote(p.username or "").strip()
        host = (p.hostname or "").strip()
        port = p.port or 443
        if not is_valid_uuid(uuid) or not host or host in ("127.0.0.1", "0.0.0.0", "localhost"):
            return None

        q = dict(urllib.parse.parse_qsl(p.query))
        if (q.get("type") or "tcp").lower() != "tcp":
            return None

        pbk = (q.get("pbk") or "").strip()
        sid = (q.get("sid") or "").strip()
        sni = (q.get("sni") or "").strip()
        if not sni or not is_valid_pbk(pbk) or not is_valid_sid(sid):
            return None

        fp = (q.get("fp") or "chrome").lower()
        if fp not in VALID_FPS:
            fp = "chrome"

        flow = (q.get("flow") or "").strip()
        if flow not in ("", "xtls-rprx-vision", "xtls-rprx-vision-udp443"):
            flow = ""

        outbound = {
            "protocol": "vless",
            "settings": {
                "vnext": [{
                    "address": host,
                    "port": port,
                    "users": [{"id": uuid, "encryption": "none", "flow": flow}]
                }]
            },
            "streamSettings": {
                "network": "tcp",
                "security": "reality",
                "realitySettings": {
                    "serverName": sni,
                    "fingerprint": fp,
                    "publicKey": pbk,
                    "shortId": sid,
                    "spiderX": "/"
                }
            }
        }
        return {"host": host, "port": port, "uri": base_uri, "outbound": outbound}
    except Exception:
        return None

def tcp_ping(node):
    t0 = time.monotonic()
    try:
        with socket.create_connection((node["host"], node["port"]), timeout=1.0):
            return (time.monotonic() - t0, node)
    except Exception:
        return None

def test_socks_traffic(args):
    port, node = args
    t0 = time.monotonic()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(2.5)
    try:
        s.connect(("127.0.0.1", port))
        s.sendall(b"\x05\x01\x00")
        if s.recv(2) != b"\x05\x00":
            return None
        target = b"connectivitycheck.gstatic.com"
        s.sendall(b"\x05\x01\x00\x03" + bytes([len(target)]) + target + struct.pack(">H", 80))
        resp = s.recv(10)
        if len(resp) < 2 or resp[1] != 0:
            return None
        s.sendall(b"GET /generate_204 HTTP/1.1\r\nHost: connectivitycheck.gstatic.com\r\nConnection: close\r\n\r\n")
        data = s.recv(256)
        if b"204" in data or b"200" in data:
            return (int((time.monotonic() - t0) * 1000), node)
    except Exception:
        return None
    finally:
        s.close()
    return None

def test_batch(batch):
    inbounds, outbounds, rules = [], [], []
    for idx, n in enumerate(batch):
        local_port = 21000 + idx
        in_tag, out_tag = f"in_{idx}", f"out_{idx}"
        inbounds.append({
            "tag": in_tag, "port": local_port, "listen": "127.0.0.1",
            "protocol": "socks", "settings": {"auth": "noauth", "udp": False}
        })
        out = json.loads(json.dumps(n["outbound"]))
        out["tag"] = out_tag
        outbounds.append(out)
        rules.append({"type": "field", "inboundTag": [in_tag], "outboundTag": out_tag})

    with open("test_xray.json", "w") as f:
        json.dump({"log": {"loglevel": "error"}, "inbounds": inbounds, "outbounds": outbounds, "routing": {"rules": rules}}, f)

    proc = subprocess.Popen(["./xray", "run", "-c", "test_xray.json"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    time.sleep(0.8)
    if proc.poll() is not None:
        print("Xray error:", proc.stdout.read().decode("utf-8", errors="ignore").strip()[-250:])
        return []

    passed = []
    try:
        tasks = [(21000 + idx, n) for idx, n in enumerate(batch)]
        with ThreadPoolExecutor(max_workers=60) as ex:
            for res in ex.map(test_socks_traffic, tasks):
                if res:
                    passed.append(res)
    finally:
        proc.terminate()
        proc.wait()
    return passed

def resolve_countries(hosts):
    mapping = {}
    unique_hosts = list(set(hosts))[:80]
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
    all_lines = []
    with ThreadPoolExecutor(max_workers=5) as ex:
        for lines in ex.map(fetch_lines, SOURCES):
            all_lines.extend(lines)

    seen = set()
    parsed_nodes = []
    for line in all_lines:
        n = parse_vless_reality(line)
        if n:
            key = (n["host"], n["port"], n["uri"][:55])
            if key not in seen:
                seen.add(key)
                parsed_nodes.append(n)

    print(f"Valid VLESS Reality nodes: {len(parsed_nodes)}")
    random.shuffle(parsed_nodes)
    with ThreadPoolExecutor(max_workers=100) as ex:
        tcp_alive = list(filter(None, ex.map(tcp_ping, parsed_nodes[:450])))

    tcp_alive.sort(key=lambda x: x[0])
    fast_nodes = [n for _, n in tcp_alive[:120]]
    print(f"TCP alive: {len(tcp_alive)}, testing top {len(fast_nodes)} via Xray...")

    verified = []
    for i in range(0, len(fast_nodes), 60):
        verified.extend(test_batch(fast_nodes[i:i + 60]))

    verified.sort(key=lambda x: x[0])
    print(f"Real traffic passed: {len(verified)} nodes!")

    if not verified:
        print("No verified nodes in this run.")
        return

    geo = resolve_countries([n["host"] for _, n in verified])
    by_country = {}
    for ms, n in verified:
        country = geo.get(n["host"], "🇪🇺 Европа")
        by_country.setdefault(country, []).append((ms, n["uri"]))

    free_links = []
    pro_links = []
    countries_json = {}

    for country, items in by_country.items():
        countries_json[country] = []
        for idx, (ms, base_uri) in enumerate(items[:4], start=1):
            label = f"{country} #{idx} ({ms}ms) • The Last VPN"
            full_uri = f"{base_uri}#{urllib.parse.quote(label)}"
            pro_links.append(full_uri)
            if idx == 1 and len(free_links) < 8:
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
