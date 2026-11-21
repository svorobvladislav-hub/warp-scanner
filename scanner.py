import socket, random, json, os, urllib.request
from concurrent.futures import ThreadPoolExecutor

SUBNETS = ["162.159.192.", "162.159.193.", "162.159.195.", "188.114.96.", "188.114.97."]
PORTS = [854, 859, 864, 894, 908, 2408, 1701, 4500]
WG_HANDSHAKE = bytes.fromhex("01000000" + "00" * 144)

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

def main():
    candidates = [(f"{sub}{random.randint(1, 254)}", random.choice(PORTS)) for sub in SUBNETS for _ in range(60)]
    with ThreadPoolExecutor(max_workers=50) as ex:
        unique_ips = list(set(filter(None, ex.map(check_endpoint, candidates))))[:100]

    worker_url = os.environ["WORKER_URL"].rstrip("/") + "/admin/update"
    req = urllib.request.Request(
        worker_url,
        data=json.dumps({"type": "raw_ips", "ips": unique_ips}).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {os.environ['ADMIN_SECRET']}",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
        },
        method="POST"
    )
    with urllib.request.urlopen(req) as resp:
        print("Saved:", len(unique_ips), resp.read().decode())

if __name__ == "__main__":
    main()
