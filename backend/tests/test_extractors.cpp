// Correctness tests for the protocol extractors and app classifier.
//
//   cd backend && ./build.sh && ./build/bin/dpi_tests
//
// Plain asserts and a counter rather than a test framework, matching the rest of
// the repo: neither service pulls in a test dependency either.
//
// This complements the fuzzing rather than duplicating it. generate_fuzz_pcap.py
// proves the extractors do not crash on malformed length fields; nothing proved
// they return the *right* answer on well-formed input, so a parser that silently
// stopped classifying would have looked healthy in CI.

#include "sni_extractor.h"
#include "types.h"

#include <cstdint>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>

using namespace DPI;

static int checks = 0;
static int failures = 0;

#define CHECK(cond, what)                                                      \
    do {                                                                       \
        ++checks;                                                              \
        if (!(cond)) {                                                         \
            ++failures;                                                        \
            std::cerr << "FAIL " << (what) << "  [" << __FILE__ << ":"         \
                      << __LINE__ << "]\n";                                    \
        }                                                                      \
    } while (0)

static void put16(std::vector<uint8_t>& v, uint16_t x) {
    v.push_back(static_cast<uint8_t>(x >> 8));
    v.push_back(static_cast<uint8_t>(x & 0xFF));
}

/** A well-formed TLS 1.2 ClientHello carrying `host` as its SNI. */
static std::vector<uint8_t> clientHello(const std::string& host) {
    std::vector<uint8_t> sni_body;
    put16(sni_body, static_cast<uint16_t>(host.size() + 3)); // list length
    sni_body.push_back(0x00);                                // name type: hostname
    put16(sni_body, static_cast<uint16_t>(host.size()));
    sni_body.insert(sni_body.end(), host.begin(), host.end());

    std::vector<uint8_t> ext;
    put16(ext, 0x0000);                                      // extension: SNI
    put16(ext, static_cast<uint16_t>(sni_body.size()));
    ext.insert(ext.end(), sni_body.begin(), sni_body.end());

    std::vector<uint8_t> body;
    put16(body, 0x0303);                                     // client version
    body.insert(body.end(), 32, 0x00);                       // random
    body.push_back(0x00);                                    // empty session id
    put16(body, 4);                                          // cipher suites length
    body.insert(body.end(), {0x13, 0x01, 0x13, 0x02});
    body.push_back(0x01);                                    // compression length
    body.push_back(0x00);
    put16(body, static_cast<uint16_t>(ext.size()));
    body.insert(body.end(), ext.begin(), ext.end());

    std::vector<uint8_t> hs;
    hs.push_back(0x01);                                      // handshake: ClientHello
    hs.push_back(static_cast<uint8_t>((body.size() >> 16) & 0xFF));
    hs.push_back(static_cast<uint8_t>((body.size() >> 8) & 0xFF));
    hs.push_back(static_cast<uint8_t>(body.size() & 0xFF));
    hs.insert(hs.end(), body.begin(), body.end());

    std::vector<uint8_t> rec;
    rec.push_back(0x16);                                     // content type: handshake
    put16(rec, 0x0301);
    put16(rec, static_cast<uint16_t>(hs.size()));
    rec.insert(rec.end(), hs.begin(), hs.end());
    return rec;
}

static void testSniExtraction() {
    for (const std::string host : {"www.youtube.com", "a.io", "sub.domain.example.co.uk"}) {
        auto rec = clientHello(host);
        CHECK(SNIExtractor::isTLSClientHello(rec.data(), rec.size()),
              "ClientHello for " + host + " should be detected");
        auto sni = SNIExtractor::extract(rec.data(), rec.size());
        CHECK(sni.has_value(), "SNI extracted for " + host);
        CHECK(sni.value_or("") == host, "SNI is exactly " + host);
    }

    // A truncated record must decline rather than return a partial hostname.
    auto rec = clientHello("www.youtube.com");
    for (size_t cut : {1u, 5u, 20u, 40u}) {
        if (cut >= rec.size()) continue;
        auto sni = SNIExtractor::extract(rec.data(), rec.size() - cut);
        CHECK(!sni.has_value() || sni->find('\0') == std::string::npos,
              "truncated ClientHello yields no malformed SNI");
    }

    const uint8_t junk[] = {0x17, 0x03, 0x03, 0x00, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05};
    CHECK(!SNIExtractor::isTLSClientHello(junk, sizeof(junk)),
          "application data is not a ClientHello");
    CHECK(!SNIExtractor::extract(junk, sizeof(junk)).has_value(),
          "non-handshake payload yields no SNI");
    CHECK(!SNIExtractor::extract(nullptr, 0).has_value(), "empty payload is safe");
}

static void testAppClassification() {
    // The mapping the dashboard's application breakdown is built from. A rename
    // or a dropped substring here is invisible until a chart goes empty.
    const std::pair<const char*, AppType> cases[] = {
        {"www.youtube.com", AppType::YOUTUBE},
        {"youtu.be", AppType::YOUTUBE},
        {"www.google.com", AppType::GOOGLE},
        {"googleapis.com", AppType::GOOGLE},
        {"www.facebook.com", AppType::FACEBOOK},
        {"www.instagram.com", AppType::INSTAGRAM},
        {"www.netflix.com", AppType::NETFLIX},
        {"www.amazon.com", AppType::AMAZON},
    };
    for (const auto& [host, expected] : cases) {
        CHECK(sniToAppType(host) == expected,
              std::string("sniToAppType(") + host + ") maps correctly");
    }

    // An unrecognised *TLS* host falls back to HTTPS, not UNKNOWN: reaching
    // this function means an SNI was extracted, so the traffic is known to be
    // encrypted web traffic even when no signature matches. Worth knowing when
    // reading the ML features -- unrecognised TLS lands in the HTTPS bucket and
    // never inflates unknown_ratio.
    CHECK(sniToAppType("no-such-domain.invalid") == AppType::HTTPS,
          "an unrecognised TLS host falls back to HTTPS");
    CHECK(sniToAppType("") == AppType::UNKNOWN, "empty SNI is UNKNOWN");

    // Regression: these matched inside a longer name and were misattributed.
    // "netflix.com" ends with "x.com", and the Twitter branch is tested first.
    CHECK(sniToAppType("www.netflix.com") == AppType::NETFLIX,
          "netflix.com is not Twitter/X (x.com substring)");
    CHECK(sniToAppType("sport.com") != AppType::TWITTER,
          "sport.com is not Twitter/X (t.co substring)");
    CHECK(sniToAppType("box.com") != AppType::TWITTER, "box.com is not Twitter/X");
    CHECK(sniToAppType("x.com") == AppType::TWITTER, "x.com itself still matches");
    CHECK(sniToAppType("api.x.com") == AppType::TWITTER,
          "a subdomain of x.com still matches");

    // Matching is case-insensitive: SNI is attacker-supplied and its case is
    // not normalised upstream.
    CHECK(sniToAppType("WWW.YOUTUBE.COM") == AppType::YOUTUBE,
          "classification ignores case");

    CHECK(appTypeToString(AppType::YOUTUBE) == "YouTube",
          "app name matches the string the dashboard groups on");
    CHECK(appTypeToString(AppType::UNKNOWN) == "Unknown",
          "UNKNOWN renders as the 'Unknown' bucket server.js reads");
}

static void testHttpHost() {
    const std::string req =
        "GET /watch HTTP/1.1\r\nHost: www.youtube.com\r\nAccept: */*\r\n\r\n";
    auto p = reinterpret_cast<const uint8_t*>(req.data());
    CHECK(HTTPHostExtractor::isHTTPRequest(p, req.size()), "GET is an HTTP request");
    auto host = HTTPHostExtractor::extract(p, req.size());
    CHECK(host.has_value() && host.value() == "www.youtube.com",
          "Host header extracted exactly");

    const std::string no_host = "GET / HTTP/1.1\r\nAccept: */*\r\n\r\n";
    auto q = reinterpret_cast<const uint8_t*>(no_host.data());
    CHECK(!HTTPHostExtractor::extract(q, no_host.size()).has_value(),
          "a request without Host yields nothing");

    const std::string tls_bytes = "\x16\x03\x01\x00\x05";
    CHECK(!HTTPHostExtractor::isHTTPRequest(
              reinterpret_cast<const uint8_t*>(tls_bytes.data()), tls_bytes.size()),
          "TLS bytes are not an HTTP request");
}

static void testDnsQuery() {
    std::vector<uint8_t> q;
    put16(q, 0x1234);
    put16(q, 0x0100);          // standard query
    put16(q, 1);               // qdcount
    put16(q, 0); put16(q, 0); put16(q, 0);
    for (const std::string label : {"www", "youtube", "com"}) {
        q.push_back(static_cast<uint8_t>(label.size()));
        q.insert(q.end(), label.begin(), label.end());
    }
    q.push_back(0x00);
    put16(q, 1); put16(q, 1);

    CHECK(DNSExtractor::isDNSQuery(q.data(), q.size()), "well-formed DNS query detected");
    auto name = DNSExtractor::extractQuery(q.data(), q.size());
    CHECK(name.has_value() && name.value() == "www.youtube.com",
          "labels reassembled with dots");

    const uint8_t short_hdr[] = {0x12, 0x34, 0x01};
    CHECK(!DNSExtractor::isDNSQuery(short_hdr, sizeof(short_hdr)),
          "a truncated header is not a query");
}

int main() {
    testSniExtraction();
    testAppClassification();
    testHttpHost();
    testDnsQuery();

    std::cout << (failures ? "FAILED " : "ok ") << (checks - failures) << "/" << checks
              << " checks\n";
    return failures ? 1 : 0;
}
