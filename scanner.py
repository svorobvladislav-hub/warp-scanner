import socket, random, json, os, urllib.request, base64
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization

SUBNETS = ["162.159.192.", "162.159.193.", "162.159.195.", "188.114.96.", "188.114.97."]
PORTS = [854, 859, 864, 894, 908, 2408, 1701, 4500]
WG_HANDSHAKE = bytes.fromhex("01000000" + "00" * 144)
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"

def check_endpoint(target):
    ip, port = target
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(1.2)
    try:
        sock.sendto(WG_HANDSHAKE, (ip, port))
        return f"{ip}:{port}"
    except Exception:
        return None
    finally:
        sock.close()

def register_warp():
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
    with urllib.request.urlopen(req, timeout=15) as resp:
        data = json.loads(resp.read().decode())

    cid = base64.b64decode(data["config"]["client_id"])
    return {
        "privateKey": priv_b64,
        "peerPublicKey": data["config"]["peers"][0]["public_key"],
        "v4": data["config"]["interface"]["addresses"]["v4"],
        "v6": data["config"]["interface"]["addresses"]["v6"],
        "reserved": [cid[0], cid[1], cid[2]]
    }

def post_worker(api_url, secret, body_dict):
    req = urllib.request.Request(
        api_url,
        data=json.dumps(body_dict).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {secret}",
            "User-Agent": UA
        },
        method="POST"
    )
    with urllib.request.urlopen(req, timeout=15) as resp:
        return resp.read().decode()

def fetch_text(url):
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=15) as resp:
        return resp.read().decode("utf-8")

def main():
    base_url = os.environ["WORKER_URL"].rstrip("/")
    secret = os.environ["ADMIN_SECRET"]

    candidates = [(f"{sub}{random.randint(1, 254)}", random.choice(PORTS)) for sub in SUBNETS for _ in range(60)]
    with ThreadPoolExecutor(max_workers=50) as ex:
        unique_ips = list(set(filter(None, ex.map(check_endpoint, candidates))))[:100]
    print("IPs:", post_worker(base_url + "/admin/update", secret, {"type": "raw_ips", "ips": unique_ips}))

    creds = register_warp()
    print("WARP:", post_worker(base_url + "/admin/update", secret, {"type": "warp_creds", "creds": creds}))

    os.makedirs("sub", exist_ok=True)
    with open("sub/free", "w", encoding="utf-8") as f:
        f.write(fetch_text(base_url + "/sub/free"))
    with open("nodes.json", "w", encoding="utf-8") as f:
        f.write(fetch_text(base_url + "/api/nodes?token=free"))
    print("Mirror files saved!")

if __name__ == "__main__":
    main()
