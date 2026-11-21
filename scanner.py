import socket, random, json, os, urllib.request, urllib.parse, base64, time, subprocess, struct, ssl
from concurrent.futures import ThreadPoolExecutor

VPN_SOURCES = [
    "https://raw.githubusercontent.com/ebrasha/free-v2ray-public-list/refs/heads/main/V2Ray-Config-By-EbraSha.txt",
    "https://raw.githubusercontent.com/yebekhe/TVC/main/subscriptions/xray/normal/vless",
    "https://raw.githubusercontent.com/yebekhe/TVC/main/subscriptions/xray/normal/trojan",
    "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/main/Protocols/vless.txt",
    "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/main/Protocols/trojan.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-Config/main/Sub1.txt",
    "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/sub/sub_merge.txt"
]

SOCKS_SOURCES = [
    "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt",
    "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt",
    "https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt",
    "https://raw.githubusercontent.com/mmpx12/proxy-list/master/socks5.txt"
]

COUNTRY_NAMES = {
    "DE": "🇩🇪 Германия", "NL": "🇳🇱 Нидерланды", "FI": "🇫🇮 Финляндия",
    "SE": "🇸🇪 Швеция", "PL": "🇵🇱 Польша", "GB": "🇬🇧 Великобритания",
    "US": "🇺🇸 США", "FR": "🇫🇷 Франция", "CH": "🇨🇭 Швейцария",
    "AT": "🇦🇹 Австрия", "CZ": "🇨🇿 Чехия", "LV": "🇱🇻 Латвия",
    "EE": "🇪🇪 Эстония", "LT": "🇱🇹 Литва", "KZ": "🇰🇿 Казахстан",
    "TR": "🇹🇷 Турция", "NO": "🇳🇴 Норвегия", "SG": "🇸🇬 Сингапур", "JP": "🇯🇵 Япония"
}

VALID_FPS = {"chrome", "firefox", "safari", "ios", "android", "edge", "random", "randomized"}
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
SSL_CTX = ssl.create_default_context()

def fetch_lines(url):
    try:
        req = urllib.request.Request(url, headers={"User-Agent": UA})
        with urllib.request.urlopen(req, timeout=10) as resp:
            raw = resp.read().decode("utf-8", errors="ignore").strip()
        if "://" not in raw and "." not in raw[:30]:
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

def parse_vpn_uri(uri):
    if not (uri.startswith("vless://") or uri.startswith("trojan://")):
        return None
    try:
        base_uri = uri.split("#", 1)[0].strip()
        p = urllib.parse.urlsplit(base_uri)
        proto = p.scheme
        cred = urllib.parse.unquote(p.username or "").strip()
        host = (p.hostname or "").strip()
        port = p.port or 443
        if not cred or not host or host in ("127.0.0.1", "0.0.0.0", "localhost"):
            return None

        q = dict(urllib.parse.parse_qsl(p.query))
        sec = (q.get("security") or ("tls" if proto == "trojan" else "none")).lower()
        net = (q.get("type") or "tcp").lower()
        if sec not in ("reality", "tls") or net not in ("tcp", "ws"):
            return None

        fp = (q.get("fp") or "chrome").lower()
        if fp not in VALID_FPS:
            fp = "chrome"

        if sec == "reality":
            pbk = (q.get("pbk") or "").strip()
            sid = (q.get("sid") or "").strip()
            sni = (q.get("sni") or "").strip()
            if net != "tcp" or not sni or not is_valid_pbk(pbk) or not is_valid_sid(sid):
                return None

        if proto == "vless":
            if not is_valid_uuid(cred):
                return None
            flow = (q.get("flow") or "").strip()
            if net != "tcp" or sec != "reality" or flow not in ("", "xtls-rprx-vision", "xtls-rprx-vision-udp443"):
                flow = ""
            outbound = {
                "protocol": "vless",
                "settings": {"vnext": [{"address": host, "port": port, "users": [{"id": cred, "encryption": "none", "flow": flow}]}]},
                "streamSettings": {"network": net, "security": sec}
            }
        else:
            outbound = {
                "protocol": "trojan",
                "settings": {"servers": [{"address": host, "port": port, "password": cred}]},
                "streamSettings": {"network": net, "security": sec}
            }

        if sec == "reality":
            outbound["streamSettings"]["realitySettings"] = {
                "serverName": q.get("sni", "").strip(),
                "fingerprint": fp,
                "publicKey": q.get("pbk", "").strip(),
                "shortId": q.get("sid", "").strip(),
                "spiderX": q.get("spx") or "/"
            }
        else:
            outbound["streamSettings"]["tlsSettings"] = {
                "serverName": (q.get("sni") or q.get("host") or host).strip(),
                "fingerprint": fp,
                "allowInsecure": True
            }

        if net == "ws":
            outbound["streamSettings"]["wsSettings"] = {
                "path": q.get("path") or "/",
                "headers": {"Host": (q.get("host") or q.get("sni") or host).strip()}
            }

        return {"host": host, "port": port, "uri": base_uri, "outbound": outbound}
    except Exception:
        return None

def check_socks5_bridge(item):
    ip, port, cc = item
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(2.5)
    t0 = time.monotonic()
    try:
        s.connect((ip, port))
        s.sendall(b"\x05\x01\x00")
        if s.recv(2) != b"\x05\x00":
            return None
        target = b"1.1.1.1"
        s.sendall(b"\x05\x01\x00\x01" + socket.inet_aton("1.1.1.1") + struct.pack(">H", 443))
        resp = s.recv(10)
        if len(resp) >= 2 and resp[1] == 0:
            ms = int((time.monotonic() - t0) * 1000)
            return (ms, ip, port, cc)
    except Exception:
        return None
    finally:
        s.close()
    return None

def find_ru_kz_bridges():
    raw_lines = []
    with ThreadPoolExecutor(max_workers=4) as ex:
        for lines in ex.map(fetch_lines, SOCKS_SOURCES):
            raw_lines.extend(lines)

    candidates = []
    seen = set()
    for line in raw_lines:
        part = line.split("://")[-1].strip()
        if ":" not in part:
            continue
        ip, port_s = part.split(":", 1)
        if not port_s.isdigit():
            continue
        port = int(port_s)
        if (ip, port) not in seen and 1 <= port <= 65535:
            seen.add((ip, port))
            candidates.append((ip, port))

    random.shuffle(candidates)
    sample = candidates[:800]
    bridges = []

    for i in range(0, len(sample), 95):
        chunk = sample[i:i + 95]
        ips = [x[0] for x in chunk]
        try:
            req = urllib.request.Request(
                "http://ip-api.com/batch?fields=query,countryCode,status",
                data=json.dumps(ips).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST"
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                geo = {r["query"]: r["countryCode"] for r in json.loads(resp.read().decode()) if r.get("status") == "success"}
            ru_kz = [(ip, port, geo[ip]) for ip, port in chunk if geo.get(ip) in ("RU", "KZ")]
            if ru_kz:
                with ThreadPoolExecutor(max_workers=40) as ex:
                    alive = list(filter(None, ex.map(check_socks5_bridge, ru_kz)))
                    bridges.extend(alive)
        except Exception:
            continue
        if len(bridges) >= 8:
            break

    bridges.sort(key=lambda x: x[0])
    print(f"Found alive RU/KZ entry bridges: {len(bridges)}")
    return bridges[:5]

def tcp_ping(node):
    t0 = time.monotonic()
    try:
        with socket.create_connection((node["host"], node["port"]), timeout=1.0):
            return (time.monotonic() - t0, node)
    except Exception:
        return None

def test_exit_https(args):
    port, node = args
    t0 = time.monotonic()
    raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    raw_sock.settimeout(3.5)
    tls_sock = None
    try:
        raw_sock.connect(("127.0.0.1", port))
        raw_sock.sendall(b"\x05\x01\x00")
        if raw_sock.recv(2) != b"\x05\x00":
            return None
        target = b"www.apple.com"
        raw_sock.sendall(b"\x05\x01\x00\x03" + bytes([len(target)]) + target + struct.pack(">H", 443))
        resp = raw_sock.recv(10)
        if len(resp) < 2 or resp[1] != 0:
            return None
        tls_sock = SSL_CTX.wrap_socket(raw_sock, server_hostname="www.apple.com")
        tls_sock.settimeout(3.5)
        tls_sock.sendall(b"GET /library/test/success.html HTTP/1.1\r\nHost: www.apple.com\r\nConnection: close\r\n\r\n")
        data = tls_sock.recv(256)
        if b"Success" in data or b"200 OK" in data:
            return (int((time.monotonic() - t0) * 1000), node)
    except Exception:
        return None
    finally:
        if tls_sock:
            try:
                tls_sock.close()
            except Exception:
                pass
        raw_sock.close()
    return None

def test_exit_batch(batch):
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
        return []

    passed = []
    try:
        tasks = [(21000 + idx, n) for idx, n in enumerate(batch)]
        with ThreadPoolExecutor(max_workers=30) as ex:
            for res in ex.map(test_exit_https, tasks):
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

def build_cascade_json(exit_node, bridge, label):
    _, b_ip, b_port, _ = bridge
    proxy_out = json.loads(json.dumps(exit_node["outbound"]))
    proxy_out["tag"] = "proxy"
    proxy_out.setdefault("streamSettings", {})["sockopt"] = {"dialerProxy": "ru-bridge"}

    return {
        "remarks": label,
        "log": {"loglevel": "warning"},
        "dns": {
            "servers": [
                {"address": "1.1.1.1", "domains": ["geosite:geolocation-!cn"]},
                {"address": "77.88.8.8", "domains": ["domain:ru", "domain:xn--p1ai"], "expectIPs": ["geoip:ru"]}
            ]
        },
        "inbounds": [
            {
                "tag": "socks",
                "port": 10808,
                "listen": "127.0.0.1",
                "protocol": "socks",
                "settings": {"auth": "noauth", "udp": True},
                "sniffing": {"enabled": True, "destOverride": ["http", "tls", "quic"]}
            }
        ],
        "outbounds": [
            proxy_out,
            {
                "tag": "ru-bridge",
                "protocol": "socks",
                "settings": {"servers": [{"address": b_ip, "port": b_port}]}
            },
            {"tag": "direct", "protocol": "freedom"},
            {"tag": "block", "protocol": "blackhole"}
        ],
        "routing": {
            "domainStrategy": "IPIfNonMatch",
            "rules": [
                {"type": "field", "domain": ["domain:ru", "domain:xn--p1ai"], "outboundTag": "direct"},
                {"type": "field", "ip": ["geoip:private", "geoip:ru"], "outboundTag": "direct"}
            ]
        }
    }

def main():
    bridges = find_ru_kz_bridges()
    if not bridges:
        print("No RU/KZ bridges found in this run.")
        return

    all_lines = []
    with ThreadPoolExecutor(max_workers=7) as ex:
        for lines in ex.map(fetch_lines, VPN_SOURCES):
            all_lines.extend(lines)

    seen = set()
    parsed = []
    for line in all_lines:
        n = parse_vpn_uri(line)
        if n:
            key = (n["host"], n["port"], n["uri"][:55])
            if key not in seen:
                seen.add(key)
                parsed.append(n)

    random.shuffle(parsed)
    with ThreadPoolExecutor(max_workers=100) as ex:
        tcp_alive = list(filter(None, ex.map(tcp_ping, parsed[:450])))

    tcp_alive.sort(key=lambda x: x[0])
    fast_exits = [n for _, n in tcp_alive[:120]]

    verified_exits = []
    for i in range(0, len(fast_exits), 30):
        verified_exits.extend(test_exit_batch(fast_exits[i:i + 30]))

    verified_exits.sort(key=lambda x: x[0])
    print(f"Verified foreign exits: {len(verified_exits)}")
    if not verified_exits:
        return

    geo = resolve_countries([n["host"] for _, n in verified_exits])
    free_configs = []
    pro_configs = []

    for idx, (ms, exit_node) in enumerate(verified_exits[:12]):
        bridge = bridges[idx % len(bridges)]
        b_flag = "🇷🇺" if bridge[3] == "RU" else "🇰🇿"
        country = geo.get(exit_node["host"], "🇪🇺 Европа")
        label = f"{b_flag} Мост → {country} ({ms}ms)"
        cfg = build_cascade_json(exit_node, bridge, label)
        pro_configs.append(cfg)
        if len(free_configs) < 6:
            free_configs.append(cfg)

    os.makedirs("sub", exist_ok=True)
    with open("sub/free", "w", encoding="utf-8") as f:
        json.dump(free_configs, f, ensure_ascii=False, indent=2)
    with open("sub/pro", "w", encoding="utf-8") as f:
        json.dump(pro_configs, f, ensure_ascii=False, indent=2)

    print(f"Built {len(free_configs)} free and {len(pro_configs)} pro cascade configs!")

if __name__ == "__main__":
    main()
