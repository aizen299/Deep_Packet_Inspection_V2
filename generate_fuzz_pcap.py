#!/usr/bin/env python3
"""Generate a malformed-payload corpus for the protocol extractors.

    pip install -r requirements-dev.txt
    python3 generate_fuzz_pcap.py            # -> fuzz_corpus.pcap
    python3 generate_fuzz_pcap.py --count 20000 --seed 7

The extractors in backend/src/sni_extractor.cpp walk attacker-controlled length
fields -- TLS session_id/cipher_suites/extension lengths, DNS label lengths,
HTTP header bounds. Every one of those is a chance to compute an offset past the
end of the buffer, and a capture file is the one input a DPI engine takes from
someone it does not trust.

Run the result through a sanitized build to make a bad bounds check crash
loudly instead of silently reading whatever follows the packet:

    cd backend && ./build.sh asan
    ./backend/build-asan/bin/dpi_engine fuzz_corpus.pcap /tmp/out.pcap --json

Cases are seeded, so a crash reproduces from the same --seed.
"""

import argparse
import random
import struct
import sys

try:
    from scapy.all import Ether, IP, TCP, UDP, Raw, wrpcap
except ImportError:
    raise SystemExit(
        "scapy is required by this generator but is not part of the stack's "
        "runtime dependencies.\n\n    pip install -r requirements-dev.txt\n"
    )


# ---- TLS ---------------------------------------------------------------------

def tls_record(body: bytes, version: int = 0x0301) -> bytes:
    """Wrap a handshake body in a TLS record whose length field is honest."""
    return b"\x16" + struct.pack(">HH", version, len(body)) + body


def client_hello(
    rng: random.Random,
    session_id_len: int = None,
    cipher_len: int = None,
    comp_len: int = None,
    ext_total_len: int = None,
    sni_list_len: int = None,
    sni_len: int = None,
    truncate: int = 0,
) -> bytes:
    """A ClientHello whose internal length fields can each be made to lie.

    Defaults produce a well-formed hello; every parameter left as None is
    filled in consistently, so a test can corrupt exactly one field and leave
    the rest valid. That isolation is what makes a crash attributable.
    """
    host = b"example.com"

    sid_len = rng.randrange(0, 32) if session_id_len is None else session_id_len
    session_id = bytes(rng.randrange(256) for _ in range(min(sid_len, 255)))

    ciphers = b"\x13\x01\x13\x02"
    c_len = len(ciphers) if cipher_len is None else cipher_len

    comp = b"\x00"
    cm_len = len(comp) if comp_len is None else comp_len

    # SNI extension: list_len, name_type, name_len, name
    s_len = len(host) if sni_len is None else sni_len
    sl_len = len(host) + 3 if sni_list_len is None else sni_list_len
    sni_body = struct.pack(">HBH", sl_len, 0x00, s_len) + host
    sni_ext = struct.pack(">HH", 0x0000, len(sni_body)) + sni_body

    exts = sni_ext
    e_len = len(exts) if ext_total_len is None else ext_total_len

    body = (
        struct.pack(">H", 0x0303)            # client version
        + bytes(32)                          # random
        + bytes([min(sid_len, 255)]) + session_id
        + struct.pack(">H", c_len) + ciphers
        + bytes([cm_len]) + comp
        + struct.pack(">H", e_len) + exts
    )

    handshake = b"\x01" + struct.pack(">I", len(body))[1:] + body  # type + uint24
    record = tls_record(handshake)
    return record[: len(record) - truncate] if truncate else record


def tls_cases(rng: random.Random) -> list:
    """Each entry lies about one length field, or truncates mid-structure."""
    big = 0xFFFF
    cases = [
        client_hello(rng),                              # control: valid
        client_hello(rng, session_id_len=255),          # session id overruns
        client_hello(rng, cipher_len=big),              # cipher suites overrun
        client_hello(rng, cipher_len=0),
        client_hello(rng, comp_len=255),                # compression overrun
        client_hello(rng, ext_total_len=big),           # extensions claim more
        client_hello(rng, ext_total_len=0),
        client_hello(rng, ext_total_len=3),             # partial ext header
        client_hello(rng, sni_list_len=big),            # SNI list overruns
        client_hello(rng, sni_list_len=0),
        client_hello(rng, sni_list_len=2),              # below the <3 guard
        client_hello(rng, sni_len=big),                 # hostname overruns
        client_hello(rng, sni_len=0),
    ]
    # Truncation at every depth: record header, handshake header, random,
    # session id, ciphers, extensions.
    full = client_hello(rng)
    for cut in (1, 2, 4, 5, 6, 8, 9, 10, 20, 40, 43, 44, 46, 50, 60):
        if cut < len(full):
            cases.append(full[:-cut])
    # A record header claiming a body that is not there.
    cases.append(b"\x16\x03\x01\xff\xff\x01\x00\x00\x00")
    cases.append(b"\x16\x03\x01\x00\x04\x01")
    return cases


# ---- DNS ---------------------------------------------------------------------

def dns_query(labels, qdcount: int = 1, truncate: int = 0, raw_tail: bytes = b"") -> bytes:
    header = struct.pack(">HHHHHH", 0x1234, 0x0100, qdcount, 0, 0, 0)
    body = b"".join(bytes([len(l)]) + l for l in labels) + b"\x00" + raw_tail
    packet = header + body + struct.pack(">HH", 1, 1)
    return packet[: len(packet) - truncate] if truncate else packet


def dns_cases(rng: random.Random) -> list:
    cases = [
        dns_query([b"example", b"com"]),                       # control
        dns_query([b"a" * 63, b"b" * 63, b"c" * 63]),          # max labels
        dns_query([], qdcount=1),                              # no labels
        dns_query([b"example", b"com"], qdcount=0xFFFF),        # lies about count
        dns_query([b"example"], truncate=4),                   # cut mid-record
        struct.pack(">HHHHHH", 1, 0x0100, 1, 0, 0, 0) + b"\x3f",   # len, no data
        struct.pack(">HHHHHH", 1, 0x0100, 1, 0, 0, 0) + b"\xff",   # >63 label
        struct.pack(">HHHHHH", 1, 0x0100, 1, 0, 0, 0) + b"\x05ab",  # claims 5, has 2
        struct.pack(">HHHHHH", 1, 0x0100, 1, 0, 0, 0),              # header only
        b"\x00" * 12,
        b"\xc0\x0c" + b"\x00" * 10,                            # compression ptr
    ]
    # A label chain that never terminates.
    cases.append(struct.pack(">HHHHHH", 1, 0x0100, 1, 0, 0, 0) + (b"\x01a" * 100))
    return cases


# ---- HTTP --------------------------------------------------------------------

def http_cases(rng: random.Random) -> list:
    return [
        b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",         # control
        b"GET / HTTP/1.1\r\nHost:",                             # header cut off
        b"GET / HTTP/1.1\r\nHost: ",                            # empty value
        b"GET / HTTP/1.1\r\nHost: " + b"a" * 5000 + b"\r\n\r\n",  # very long host
        b"GET / HTTP/1.1\r\nHost: a\rb\nc\r\n\r\n",             # embedded CR/LF
        b"GET / HTTP/1.1\r\n" + b"X: y\r\n" * 500 + b"\r\n",    # many headers
        b"GET / HTTP/1.1\r\nHost: exa\x00mple.com\r\n\r\n",     # NUL in value
        b"GET",                                                 # truncated method
        b"GET / HTTP/1.1",                                      # no headers at all
        b"POST / HTTP/1.1\r\nhost: lowercase.com\r\n\r\n",      # case variance
        b"\r\n\r\n",
        b"GET / HTTP/1.1\r\nHost: example.com",                 # no terminator
    ]


# ---- assembly ----------------------------------------------------------------

def random_noise(rng: random.Random, n: int) -> list:
    """Unstructured payloads on parsed ports, to hit the detectors themselves."""
    out = []
    for _ in range(n):
        size = rng.choice([0, 1, 2, 3, 4, 5, 8, 11, 12, 40, 64, 500, 1400])
        out.append(bytes(rng.randrange(256) for _ in range(size)))
    return out


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", default="fuzz_corpus.pcap")
    ap.add_argument("--count", type=int, default=6000,
                    help="random noise packets added on top of the structured cases")
    ap.add_argument("--seed", type=int, default=1337)
    args = ap.parse_args()

    rng = random.Random(args.seed)
    packets = []

    def emit(payload: bytes, dport: int, proto="tcp"):
        ip = IP(src=f"10.0.0.{rng.randrange(1, 254)}", dst="192.168.1.10")
        l4 = TCP(sport=rng.randrange(1024, 65535), dport=dport, flags="PA") \
            if proto == "tcp" else UDP(sport=rng.randrange(1024, 65535), dport=dport)
        packets.append(Ether() / ip / l4 / Raw(load=payload))

    structured = 0
    for payload in tls_cases(rng):
        emit(payload, 443)
        structured += 1
    for payload in http_cases(rng):
        emit(payload, 80)
        structured += 1
    for payload in dns_cases(rng):
        emit(payload, 53, proto="udp")
        structured += 1

    # The same malformed payloads on the wrong port, so classification order
    # (TLS -> HTTP -> DNS -> port fallback) is exercised too.
    for payload in tls_cases(rng):
        emit(payload, 53, proto="udp")
        structured += 1
    for payload in dns_cases(rng):
        emit(payload, 443)
        structured += 1

    for payload in random_noise(rng, args.count):
        emit(payload, rng.choice([80, 443, 53, 8080]),
             proto=rng.choice(["tcp", "udp"]))

    wrpcap(args.out, packets)
    print(f"wrote {args.out}")
    print(f"  {structured} structured malformed cases")
    print(f"  {args.count} random noise packets")
    print(f"  {len(packets)} total, seed={args.seed}")


if __name__ == "__main__":
    main()
