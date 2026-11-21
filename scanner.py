import os, json, base64, urllib.request
from datetime import datetime, timezone
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization

ENDPOINTS = [
    ("162.159.192.1:2408", "🇩🇪 Германия #1"),
    ("162.159.192.12:854", "🇩🇪 Германия #2"),
    ("162.159.193.10:859", "🇳🇱 Нидерланды #1"),
    ("162.159.193.45:894", "🇳🇱 Нидерланды #2"),
    ("188.114.96.5:894", "🇫🇮 Финляндия #1"),
    ("188.114.97.12:908", "🇸🇪 Швеция #1"),
    ("162.159.195.2:859", "🇰🇿 Казахстан #1"),
    ("188.114.98.224:1701", "🇵🇱 Польша #1")
]

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

def build_amnezia_conf(creds, endpoint):
    return f"""[Interface]
PrivateKey = {creds['privateKey']}
Address = {creds['v4']}/32, {creds['v6']}/128
DNS = 1.1.1.1, 8.8.8.8
MTU = 1280
Jc = 5
Jmin = 40
Jmax = 70
S1 = 0
S2 = 0
H1 = 1
H2 = 2
H3 = 3
H4 = 4

[Peer]
PublicKey = {creds['peerPublicKey']}
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = {endpoint}
PersistentKeepalive = 25
"""

def build_hiddify_json(creds):
    outbounds = []
    selector_tags = []
    for idx, (ep, label) in enumerate(ENDPOINTS, start=1):
        tag = f"warp_{idx}"
        host, port = ep.split(":")
        selector_tags.append(tag)
        outbounds.append({
            "type": "wireguard",
            "tag": tag,
            "server": host,
            "server_port": int(port),
            "local_address": [f"{creds['v4']}/32", f"{creds['v6']}/128"],
            "private_key": creds["privateKey"],
            "peer_public_key": creds["peerPublicKey"],
            "reserved": creds["reserved"],
            "mtu": 1280,
            "fake_packets": "5-10",
            "fake_packets_size": "40-70",
            "fake_packets_delay": "10-20"
        })

    return {
        "dns": {
            "servers": [
                {"tag": "remote", "address": "1.1.1.1", "detour": "select"},
                {"tag": "local", "address": "77.88.8.8", "detour": "direct"}
            ],
            "rules": [{"domain_suffix": [".ru", ".xn--p1ai"], "server": "local"}]
        },
        "inbounds": [
            {"type": "tun", "tag": "tun-in", "inet4_address": "172.19.0.1/30", "auto_route": True, "strict_route": True, "stack": "system", "sniff": True}
        ],
        "outbounds": [
            {"type": "selector", "tag": "select", "outbounds": ["auto"] + selector_tags, "default": "auto"},
            {"type": "urltest", "tag": "auto", "outbounds": selector_tags, "url": "https://www.gstatic.com/generate_204", "interval": "3m"},
            *outbounds,
            {"type": "direct", "tag": "direct"},
            {"type": "block", "tag": "block"}
        ],
        "route": {
            "auto_detect_interface": True,
            "rules": [
                {"domain_suffix": [".ru", ".xn--p1ai"], "outbound": "direct"}
            ]
        }
    }

def main():
    creds = register_warp()
    os.makedirs("sub", exist_ok=True)

    with open("warp.conf", "w", encoding="utf-8") as f:
        f.write(build_amnezia_conf(creds, ENDPOINTS[0][0]))

    with open("sub/hiddify.json", "w", encoding="utf-8") as f:
        json.dump(build_hiddify_json(creds), f, ensure_ascii=False, indent=2)

    print("WARP + AmneziaWG configs generated successfully!")

if __name__ == "__main__":
    main()
