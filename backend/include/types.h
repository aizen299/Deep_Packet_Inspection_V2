#ifndef DPI_TYPES_H
#define DPI_TYPES_H

#include <cstdint>
#include <string>
#include <functional>
#include <chrono>
#include <vector>
#include <atomic>
#include <optional>
#include <array>

namespace DPI {

struct FiveTuple {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t  protocol;
    
    bool operator==(const FiveTuple& other) const {
        return src_ip == other.src_ip &&
               dst_ip == other.dst_ip &&
               src_port == other.src_port &&
               dst_port == other.dst_port &&
               protocol == other.protocol;
    }
    
    FiveTuple reverse() const {
        return {dst_ip, src_ip, dst_port, src_port, protocol};
    }
    
    std::string toString() const;

    bool isValid() const {
        return protocol != 0 && (src_port != 0 || dst_port != 0);
    }

    uint64_t compactHashKey() const {
        return (static_cast<uint64_t>(src_ip) << 32) ^
               (static_cast<uint64_t>(dst_ip)) ^
               (static_cast<uint64_t>(src_port) << 16) ^
               (static_cast<uint64_t>(dst_port)) ^
               protocol;
    }
};

struct FiveTupleHash {
    size_t operator()(const FiveTuple& tuple) const noexcept {
        uint64_t key = tuple.compactHashKey();
        key ^= key >> 33;
        key *= 0xff51afd7ed558ccdULL;
        key ^= key >> 33;
        key *= 0xc4ceb9fe1a85ec53ULL;
        key ^= key >> 33;
        return static_cast<size_t>(key);
    }
};

enum class AppType {
    UNKNOWN = 0,
    HTTP,
    HTTPS,
    DNS,
    TLS,
    QUIC,
    GOOGLE,
    FACEBOOK,
    YOUTUBE,
    TWITTER,
    INSTAGRAM,
    NETFLIX,
    AMAZON,
    MICROSOFT,
    APPLE,
    WHATSAPP,
    TELEGRAM,
    TIKTOK,
    SPOTIFY,
    ZOOM,
    DISCORD,
    GITHUB,
    CLOUDFLARE,
    APP_COUNT
};

std::string appTypeToString(AppType type);
AppType sniToAppType(const std::string& sni);

enum class ConnectionState {
    NEW,
    ESTABLISHED,
    CLASSIFIED,
    BLOCKED,
    CLOSED
};

enum class PacketAction {
    FORWARD,
    DROP,
    INSPECT,
    LOG_ONLY
};

struct Connection {
    FiveTuple tuple;
    ConnectionState state = ConnectionState::NEW;
    AppType app_type = AppType::UNKNOWN;
    std::string sni;
    
    uint64_t packets_in = 0;
    uint64_t packets_out = 0;
    uint64_t bytes_in = 0;
    uint64_t bytes_out = 0;
    
    std::chrono::steady_clock::time_point first_seen;
    std::chrono::steady_clock::time_point last_seen;
    
    PacketAction action = PacketAction::FORWARD;
    
    bool syn_seen = false;
    bool syn_ack_seen = false;
    bool fin_seen = false;
    bool rst_seen = false;
    uint64_t last_activity_ns = 0;
    double average_packet_size = 0.0;
};

struct PacketJob {
    uint32_t packet_id;
    FiveTuple tuple;
    std::vector<uint8_t> data;
    size_t eth_offset = 0;
    size_t ip_offset = 0;
    size_t transport_offset = 0;
    size_t payload_offset = 0;
    size_t payload_length = 0;
    uint8_t tcp_flags = 0;
    const uint8_t* payload_data = nullptr;
    bool is_fragmented = false;
    bool is_malformed = false;
    
    uint32_t ts_sec;
    uint32_t ts_usec;
};

struct DPIStats {
    std::atomic<uint64_t> total_packets{0};
    std::atomic<uint64_t> total_bytes{0};
    std::atomic<uint64_t> forwarded_packets{0};
    std::atomic<uint64_t> dropped_packets{0};
    std::atomic<uint64_t> tcp_packets{0};
    std::atomic<uint64_t> udp_packets{0};
    std::atomic<uint64_t> other_packets{0};
    std::atomic<uint64_t> active_connections{0};
    std::atomic<uint64_t> malformed_packets{0};
    std::atomic<uint64_t> fragmented_packets{0};
    std::atomic<uint64_t> rule_block_events{0};
    
    DPIStats() = default;
    DPIStats(const DPIStats&) = delete;
    DPIStats& operator=(const DPIStats&) = delete;
};

}

#endif
