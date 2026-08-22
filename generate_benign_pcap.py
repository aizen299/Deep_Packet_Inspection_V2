#!/usr/bin/env python3
"""Generate realistic benign captures for training the anomaly scorer.

    pip install -r requirements-dev.txt
    python3 generate_benign_pcap.py --out benign.pcap --sessions 40 --seed 1

The scorer is an IsolationForest trained on normal traffic only, so the corpus
defines what "normal" means. The other generators here are deliberately hostile
-- generate_fuzz_pcap.py corrupts length fields, generate_attack_pcap.py floods
-- and both produce roughly one packet per connection, which is exactly the
shape the model should flag. Training on those would teach it that scans are
ordinary.

What makes traffic look benign to this engine:

  * complete TCP sessions -- handshake, data, teardown -- so packets per
    connection lands in the tens rather than at 1
  * SNI and Host values the classifier recognises, keeping unknown_ratio low
  * a spread of applications rather than a single destination

Per-capture parameters are randomised, so a set of captures produced with
different seeds gives the corpus its spread rather than clustering on one point.
"""

import argparse
import random
import struct

try:
    from scapy.all import Ether, IP, TCP, UDP, Raw, wrpcap
except ImportError:
    raise SystemExit(
        "scapy is required by this generator but is not part of the stack's "
        "runtime dependencies.\n\n    pip install -r requirements-dev.txt\n"
    )

# Hostnames the classifier in backend/src/types.cpp maps to an application.
# Keeping to recognised names is the point: unknown_ratio is a feature, and a
# corpus of unclassifiable traffic would make "unknown" look normal.
HOSTS = [
    b"www.google.com", b"googleapis.com", b"gstatic.com",
    b"www.youtube.com", b"youtu.be", b"ggpht.com",
    b"www.facebook.com", b"fbcdn.net",
    b"www.instagram.com", b"cdninstagram.com",
    b"twitter.com", b"twimg.com", b"x.com",
    b"www.netflix.com", b"nflximg.net",
    b"www.amazon.com", b"amazonaws.com", b"cloudfront.net",
    b"www.apple.com", b"icloud.com", b"mzstatic.com",
    b"www.microsoft.com", b"outlook.com", b"office.com",
    b"web.whatsapp.com", b"telegram.org", b"www.tiktok.com",
]


def client_hello(host: bytes) -> bytes:
    """A well-formed TLS 1.2 ClientHello carrying `host` as SNI."""
    sni_body = struct.pack(">HBH", len(host) + 3, 0x00, len(host)) + host
    sni_ext = struct.pack(">HH", 0x0000, len(sni_body)) + sni_body

    ciphers = b"\x13\x01\x13\x02\xc0\x2f\xc0\x30"
    body = (
        struct.pack(">H", 0x0303)
        + bytes(32)
        + b"\x00"                                   # empty session id
        + struct.pack(">H", len(ciphers)) + ciphers
        + b"\x01\x00"                               # one compression method
        + struct.pack(">H", len(sni_ext)) + sni_ext
    )
    handshake = b"\x01" + struct.pack(">I", len(body))[1:] + body
    return b"\x16\x03\x01" + struct.pack(">H", len(handshake)) + handshake


def http_request(host: bytes, path: bytes = b"/") -> bytes:
    return (
        b"GET " + path + b" HTTP/1.1\r\n"
        b"Host: " + host + b"\r\n"
        b"User-Agent: Mozilla/5.0\r\n"
        b"Accept: */*\r\n"
        b"Connection: keep-alive\r\n\r\n"
    )


def dns_query(host: bytes) -> bytes:
    labels = b"".join(bytes([len(p)]) + p for p in host.split(b".")) + b"\x00"
    return (
        struct.pack(">HHHHHH", random.randrange(65536), 0x0100, 1, 0, 0, 0)
        + labels
        + struct.pack(">HH", 1, 1)
    )


def tcp_session(rng, client_ip, server_ip, sport, dport, payloads, close=True):
    """A complete session: handshake, payload exchange, teardown.

    The packet count per connection is the point -- a scan produces one, a real
    session produces tens, and that ratio is one of the model's features.
    """
    eth = Ether()
    c2s = lambda **kw: eth / IP(src=client_ip, dst=server_ip) / TCP(
        sport=sport, dport=dport, **kw)
    s2c = lambda **kw: eth / IP(src=server_ip, dst=client_ip) / TCP(
        sport=dport, dport=sport, **kw)

    seq, ack = rng.randrange(1 << 30), rng.randrange(1 << 30)
    out = [
        c2s(flags="S", seq=seq),
        s2c(flags="SA", seq=ack, ack=seq + 1),
        c2s(flags="A", seq=seq + 1, ack=ack + 1),
    ]
    seq += 1
    ack += 1

    for i, payload in enumerate(payloads):
        out.append(c2s(flags="PA", seq=seq, ack=ack) / Raw(load=payload))
        seq += len(payload)
        # Server responds with a few segments, as a real transfer would.
        for _ in range(rng.randrange(1, 4)):
            chunk = bytes(rng.randrange(256) for _ in range(rng.randrange(200, 1400)))
            out.append(s2c(flags="PA", seq=ack, ack=seq) / Raw(load=chunk))
            ack += len(chunk)
        out.append(c2s(flags="A", seq=seq, ack=ack))

    # Only some sessions are torn down. A FIN moves the connection to CLOSED
    # and the tracker then reaps it, so a capture where everything closes
    # reports almost no active connections -- which is not what stopping a
    # capture mid-browse actually looks like.
    if close:
        out.append(c2s(flags="FA", seq=seq, ack=ack))
        out.append(s2c(flags="FA", seq=ack, ack=seq + 1))
        out.append(c2s(flags="A", seq=seq + 1, ack=ack + 1))
    return out


def build_capture(rng, sessions: int):
    packets = []
    for _ in range(sessions):
        host = rng.choice(HOSTS)
        client = f"192.168.1.{rng.randrange(2, 250)}"
        server = f"142.250.{rng.randrange(0, 255)}.{rng.randrange(1, 254)}"
        sport = rng.randrange(1024, 65535)

        # A name lookup usually precedes the connection.
        if rng.random() < 0.6:
            packets.append(
                Ether() / IP(src=client, dst="192.168.1.1")
                / UDP(sport=rng.randrange(1024, 65535), dport=53)
                / Raw(load=dns_query(host))
            )

        if rng.random() < 0.8:
            payloads = [client_hello(host)]
            dport = 443
        else:
            payloads = [http_request(host)]
            dport = 80

        # Keep-alive sessions carry several requests.
        for _ in range(rng.randrange(0, 4)):
            payloads.append(
                client_hello(host) if dport == 443 else http_request(host, b"/asset")
            )

        packets.extend(
            tcp_session(rng, client, server, sport, dport, payloads,
                        close=rng.random() < 0.35)
        )
    return packets


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", default="benign.pcap")
    ap.add_argument("--sessions", type=int, default=0,
                    help="0 picks a random count, giving the corpus spread")
    ap.add_argument("--seed", type=int, default=1)
    args = ap.parse_args()

    rng = random.Random(args.seed)
    random.seed(args.seed)  # dns_query uses the module-level rng for its txid

    sessions = args.sessions or rng.choice([3, 5, 8, 12, 20, 30, 45, 70, 110])
    packets = build_capture(rng, sessions)
    wrpcap(args.out, packets)
    print(f"wrote {args.out}: {sessions} sessions, {len(packets)} packets")


if __name__ == "__main__":
    main()
