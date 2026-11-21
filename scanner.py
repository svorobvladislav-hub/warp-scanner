import socket, random, json, os, urllib.request, urllib.parse, base64, time, subprocess, struct
from concurrent.futures import ThreadPoolExecutor

SOURCES = [
    "https://raw.githubusercontent.com/ebrasha/free-v2ray-public-list/refs/heads/main/V2Ray-Config-By-EbraSha.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-Config/main/Sub1.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-Config/main/Sub2.txt",
    "https://raw.githubusercontent.com/yebekhe/TVC/main/subscriptions/xray/normal/vless",
    "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/main/Protocols/vless.txt",
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

def parse_vless(uri):
    if not uri.startswith("vless://"):
        return None
    try:
        base_uri = uri.split("#", 1)[0]
        p = urllib.parse.urlsplit(base_uri)
        uuid = p.username
        host = p.hostname
        port = p.port or 443
        if not uuid or not host or host in ("127.0.0.1", "0.0.0.0", "localhost"):
            return None
        q = dict(urllib.parse.parse_qsl(p.query))
        sec = q.get("security", "none")
        net = q.get("type", "tcp")
        if sec not in ("reality", "tls"):
            return None
        if sec == "reality" and not q.get("pbk"):
            return None

        outbound = {
            "protocol": "vless",
            "settings": {
                "vnext": [{
                    "address": host,
                    "port": port,
                    "users": [{
                        "id": uuid,
                        "encryption": "none",
                        "flow": q.get("flow", "")
                    }]
                }]
            },
            "streamSettings": {
                "network": net,
                "security": sec
            }
        }

        if sec == "reality":
            outbound["streamSettings"]["realitySettings"] = {
                "serverName": q.get("sni", ""),
                "fingerprint": q.get("fp", "chrome"),
                "publicKey": q.get("pbk", ""),
                "shortId": q.get("sid", ""),
                "spiderX": q.get("spx", "/")
            }
        elif sec == "tls":
            outbound["streamSettings"]["tlsSettings"] = {
                "serverName": q.get("sni", host),
                "fingerprint": q.get("fp", "chrome"),
                "allowInsecure": True
            }

        if net == "ws":
            outbound["streamSettings"]["wsSettings"] = {
                "path": q.get("path", "/"),
                "headers": {"Host": q.get("host", q.get("sni", host))}
            }
        elif net == "grpc":
            outbound["streamSettings"]["grpcSettings"] = {
                "serviceName": q.get("serviceName", "")
            }

        return {"host": host, "port": port, "uri": base_uri, "outbound": outbound}
    except Exception:
        return None

def tcp_ping(node):
    try:
        with socket.create_connection((node["host"], node["port"]), timeout=1.2):
            return node
    except Exception:
        return None

def test_socks_traffic(args):
    port, node = args
    t0 = time.monotonic()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(4.0)
    try:
        s.connect(("127.0.0.1", port))
        s.sendall(b"\x05\x01\x00")
        if s.recv(2) != b"\x05\x00":
            return None
        target = b"cp.cloudflare.com"
        req = b"\x05\x01\x00\x03" + bytes([len(target)]) + target + struct.pack(">H", 80)
        s.sendall(req)
        resp = s.recv(10)
        if len(resp) < 2 or resp[1] != 0:
            return None
        s.sendall(b"GET /generate_204 HTTP/1.1\r\nHost: cp.cloudflare.com\r\nConnection: close\r\n\r\n")
        data = s.recv(256)
        if b"204" in data or b"200" in data:
            ms = int((time.monotonic() - t0) * 1000)
            return (ms, node)
    except Exception:
        return None
    finally:
        s.close()
    return None

def verify_batch_with_xray(nodes):
    verified = []
    batch_size = 35
    for i in range(0, len(nodes), batch_size):
        batch = nodes[i:i + batch_size]
        inbounds = []
        outbounds = []
        rules = []
        for idx, n in enumerate(batch):
            local_port = 21000 + idx
            in_tag = f"in_{idx}"
            out_tag = f"out_{idx}"
            inbounds.append({
                "tag": in_tag, "port": local_port, "listen": "127.0.0.1",
                "protocol": "socks", "settings": {"auth": "noauth", "udp": False}
            })
            out = json.loads(json.dumps(n["outbound"]))
            out["tag"] = out_tag
            outbounds.append(out)
            rules.append({"type": "field", "inboundTag": [in_tag], "outboundTag": out_tag})

        cfg = {
            "log": {"loglevel": "none"},
            "inbounds": inbounds,
            "outbounds": outbounds,
            "routing": {"rules": rules}
        }
        with open("test_xray.json", "w") as f:
            json.dump(cfg, f)

        proc = subprocess.Popen(["./xray", "-c", "test_xray.json"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(1.5)
        try:
            tasks = [(21000 + idx, n) for idx, n in enumerate(batch)]
            with ThreadPoolExecutor(max_workers=20) as ex:
                for res in ex.map(test_socks_traffic, tasks):
                    if res:
                        verified.append(res)
        finally:
            proc.terminate()
            proc.wait()
        if len(verified) >= 25:
            break
    return verified

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
        with urllib.request.urlopen(req, timeout=12) as resp:
            for r in json.loads(resp.read().decode()):
                if r.get("status") == "success":
                    code = r.get("countryCode", "")
                    mapping[r["query"]] = COUNTRY_NAMES.get(code, f"🌍 Европа ({code})")
    except Exception:
        pass
    return mapping

def main():
    all_lines = []
    with ThreadPoolExecutor(max_workers=6) as ex:
        for lines in ex.map(fetch_lines, SOURCES):
            all_lines.extend(lines)

    seen = set()
    parsed_nodes = []
    for line in all_lines:
        n = parse_vless(line)
        if n:
            key = (n["host"], n["port"], n["uri"][:55])
            if key not in seen:
                seen.add(key)
                parsed_nodes.append(n)

    random.shuffle(parsed_nodes)
    with ThreadPoolExecutor(max_workers=60) as ex:
        tcp_alive = list(filter(None, ex.map(tcp_ping, parsed_nodes[:350])))

    print(f"TCP alive: {len(tcp_alive)}, testing real traffic via Xray...")
    verified = verify_batch_with_xray(tcp_alive[:140])
    verified.sort(key=lambda x: x[0])
    print(f"Real traffic passed: {len(verified)} nodes!")

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
