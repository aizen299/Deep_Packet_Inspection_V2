#ifndef SNI_EXTRACTOR_H
#define SNI_EXTRACTOR_H

#include <string>
#include <cstdint>
#include <optional>
#include <vector>
#include <cstddef>
#include <string_view>

namespace DPI {

class SNIExtractor {
public:
    static std::optional<std::string> extract(const uint8_t* payload, size_t length);
    static bool isTLSClientHello(const uint8_t* payload, size_t length);
    static std::vector<std::pair<uint16_t, std::string>> extractExtensions(
        const uint8_t* payload, size_t length);
    static bool validateClientHello(const uint8_t* payload, size_t length);
    static constexpr size_t MAX_SNI_LENGTH = 255;
    static constexpr size_t MAX_EXTENSION_TOTAL_LENGTH = 8192;

private:
    static constexpr uint8_t CONTENT_TYPE_HANDSHAKE = 0x16;
    static constexpr uint8_t HANDSHAKE_CLIENT_HELLO = 0x01;
    static constexpr uint16_t EXTENSION_SNI = 0x0000;
    static constexpr uint8_t SNI_TYPE_HOSTNAME = 0x00;
    
    static uint16_t readUint16BE(const uint8_t* data);
    static uint32_t readUint24BE(const uint8_t* data);
    static bool safeBoundsCheck(size_t offset, size_t required, size_t total);
};

class QUICSNIExtractor {
public:
    static std::optional<std::string> extract(const uint8_t* payload, size_t length);
    static bool isQUICInitial(const uint8_t* payload, size_t length);
    static constexpr size_t MAX_CRYPTO_FRAME_SCAN = 16384;
};

class HTTPHostExtractor {
public:
    static std::optional<std::string> extract(const uint8_t* payload, size_t length);
    static bool isHTTPRequest(const uint8_t* payload, size_t length);
    static constexpr size_t MAX_HTTP_HEADER_SCAN = 16384;
};

class DNSExtractor {
public:
    static std::optional<std::string> extractQuery(const uint8_t* payload, size_t length);
    static bool isDNSQuery(const uint8_t* payload, size_t length);
    static constexpr size_t MAX_DNS_LABEL_DEPTH = 50;
    static constexpr size_t MAX_DNS_NAME_LENGTH = 255;
};

}

#endif
