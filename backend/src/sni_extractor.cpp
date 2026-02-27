#include "sni_extractor.h"
#include <cstring>
#include <algorithm>

namespace DPI {

uint16_t SNIExtractor::readUint16BE(const uint8_t* data) {
    return (static_cast<uint16_t>(data[0]) << 8) | data[1];
}

uint32_t SNIExtractor::readUint24BE(const uint8_t* data) {
    return (static_cast<uint32_t>(data[0]) << 16) |
           (static_cast<uint32_t>(data[1]) << 8) |
           data[2];
}

bool SNIExtractor::isTLSClientHello(const uint8_t* payload, size_t length) {
    if (length < 9) return false;
    
    if (payload[0] != CONTENT_TYPE_HANDSHAKE) return false;
    
    uint16_t version = readUint16BE(payload + 1);
    if (version < 0x0300 || version > 0x0304) return false;
    
    uint16_t record_length = readUint16BE(payload + 3);
    if (record_length > length - 5) return false;
    
    if (payload[5] != HANDSHAKE_CLIENT_HELLO) return false;
    
    return true;
}

std::optional<std::string> SNIExtractor::extract(const uint8_t* payload, size_t length) {
    if (!isTLSClientHello(payload, length)) {
        return std::nullopt;
    }
    
    size_t offset = 5;
    
    uint32_t handshake_length = readUint24BE(payload + offset + 1);
    offset += 4;
    
    offset += 2;
    
    offset += 32;
    
    if (offset >= length) return std::nullopt;
    uint8_t session_id_length = payload[offset];
    offset += 1 + session_id_length;
    
    if (offset + 2 > length) return std::nullopt;
    uint16_t cipher_suites_length = readUint16BE(payload + offset);
    offset += 2 + cipher_suites_length;
    
    if (offset >= length) return std::nullopt;
    uint8_t compression_methods_length = payload[offset];
    offset += 1 + compression_methods_length;
    
    if (offset + 2 > length) return std::nullopt;
    uint16_t extensions_length = readUint16BE(payload + offset);
    offset += 2;
    
    size_t extensions_end = offset + extensions_length;
    if (extensions_end > length) {
        extensions_end = length;
    }
    
    while (offset + 4 <= extensions_end) {
        uint16_t extension_type = readUint16BE(payload + offset);
        uint16_t extension_length = readUint16BE(payload + offset + 2);
        offset += 4;
        
        if (offset + extension_length > extensions_end) break;
        
        if (extension_type == EXTENSION_SNI) {
            if (extension_length < 5) break;
            
            uint16_t sni_list_length = readUint16BE(payload + offset);
            if (sni_list_length < 3) break;
            
            uint8_t sni_type = payload[offset + 2];
            uint16_t sni_length = readUint16BE(payload + offset + 3);
            
            if (sni_type != SNI_TYPE_HOSTNAME) break;
            if (sni_length > extension_length - 5) break;
            
            std::string sni(reinterpret_cast<const char*>(payload + offset + 5), sni_length);
            return sni;
        }
        
        offset += extension_length;
    }
    
    return std::nullopt;
}

std::vector<std::pair<uint16_t, std::string>> SNIExtractor::extractExtensions(
    const uint8_t* payload, size_t length) {
    
    std::vector<std::pair<uint16_t, std::string>> extensions;
    
    return extensions;
}

bool HTTPHostExtractor::isHTTPRequest(const uint8_t* payload, size_t length) {
    if (length < 4) return false;
    
    const char* methods[] = {"GET ", "POST", "PUT ", "HEAD", "DELE", "PATC", "OPTI"};
    
    for (const char* method : methods) {
        if (std::memcmp(payload, method, 4) == 0) {
            return true;
        }
    }
    
    return false;
}

std::optional<std::string> HTTPHostExtractor::extract(const uint8_t* payload, size_t length) {
    if (!isHTTPRequest(payload, length)) {
        return std::nullopt;
    }
    
    const char* host_header = "Host: ";
    const size_t host_header_len = 6;
    
    for (size_t i = 0; i + host_header_len < length; i++) {
        if ((payload[i] == 'H' || payload[i] == 'h') &&
            (payload[i+1] == 'o' || payload[i+1] == 'O') &&
            (payload[i+2] == 's' || payload[i+2] == 'S') &&
            (payload[i+3] == 't' || payload[i+3] == 'T') &&
            payload[i+4] == ':') {
            
            size_t start = i + 5;
            while (start < length && (payload[start] == ' ' || payload[start] == '\t')) {
                start++;
            }
            
            size_t end = start;
            while (end < length && payload[end] != '\r' && payload[end] != '\n') {
                end++;
            }
            
            if (end > start) {
                std::string host(reinterpret_cast<const char*>(payload + start), end - start);
                
                size_t colon_pos = host.find(':');
                if (colon_pos != std::string::npos) {
                    host = host.substr(0, colon_pos);
                }
                
                return host;
            }
        }
    }
    
    return std::nullopt;
}

bool DNSExtractor::isDNSQuery(const uint8_t* payload, size_t length) {
    if (length < 12) return false;
    
    uint8_t flags = payload[2];
    if (flags & 0x80) return false;
    
    uint16_t qdcount = (static_cast<uint16_t>(payload[4]) << 8) | payload[5];
    if (qdcount == 0) return false;
    
    return true;
}

std::optional<std::string> DNSExtractor::extractQuery(const uint8_t* payload, size_t length) {
    if (!isDNSQuery(payload, length)) {
        return std::nullopt;
    }
    
    size_t offset = 12;
    std::string domain;
    
    while (offset < length) {
        uint8_t label_length = payload[offset];
        
        if (label_length == 0) {
            break;
        }
        
        if (label_length > 63) {
            break;
        }
        
        offset++;
        if (offset + label_length > length) break;
        
        if (!domain.empty()) {
            domain += '.';
        }
        domain += std::string(reinterpret_cast<const char*>(payload + offset), label_length);
        offset += label_length;
    }
    
    return domain.empty() ? std::nullopt : std::optional<std::string>(domain);
}

bool QUICSNIExtractor::isQUICInitial(const uint8_t* payload, size_t length) {
    if (length < 5) return false;
    
    uint8_t first_byte = payload[0];
    
    if ((first_byte & 0x80) == 0) return false;
    
    return true;
}

std::optional<std::string> QUICSNIExtractor::extract(const uint8_t* payload, size_t length) {
    if (!isQUICInitial(payload, length)) {
        return std::nullopt;
    }
    
    for (size_t i = 0; i + 50 < length; i++) {
        if (payload[i] == 0x01) {
            auto result = SNIExtractor::extract(payload + i - 5, length - i + 5);
            if (result) return result;
        }
    }
    
    return std::nullopt;
}

}
