#ifndef PACKET_PARSER_H
#define PACKET_PARSER_H

#include <cstdint>
#include <string>
#include <array>
#include <optional>
#include <string_view>
#include "pcap_reader.h"

namespace PacketAnalyzer {

struct EthernetHeader {
    std::array<uint8_t, 6> dest_mac;
    std::array<uint8_t, 6> src_mac;
    uint16_t ether_type;
};

struct IPv4Header {
    uint8_t  version_ihl;
    uint8_t  tos;
    uint16_t total_length;
    uint16_t identification;
    uint16_t flags_fragment;
    uint8_t  ttl;
    uint8_t  protocol;
    uint16_t checksum;
    uint32_t src_ip;
    uint32_t dest_ip;
};

struct IPv6Header {
    uint32_t version_tc_flow;
    uint16_t payload_length;
    uint8_t  next_header;
    uint8_t  hop_limit;
    std::array<uint8_t, 16> src_ip;
    std::array<uint8_t, 16> dest_ip;
};

struct TCPHeader {
    uint16_t src_port;
    uint16_t dest_port;
    uint32_t seq_number;
    uint32_t ack_number;
    uint8_t  data_offset;
    uint8_t  flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent_pointer;
};

struct UDPHeader {
    uint16_t src_port;
    uint16_t dest_port;
    uint16_t length;
    uint16_t checksum;
};

struct ParsedPacket {
    uint32_t timestamp_sec;
    uint32_t timestamp_usec;

    std::string src_mac;
    std::string dest_mac;
    uint16_t ether_type;

    bool has_ip = false;
    bool has_ipv4 = false;
    bool has_ipv6 = false;

    uint8_t ip_version = 0;
    std::string src_ip;
    std::string dest_ip;
    uint8_t protocol = 0;
    uint8_t ttl = 0;

    bool has_tcp = false;
    bool has_udp = false;

    uint16_t src_port = 0;
    uint16_t dest_port = 0;

    uint8_t tcp_flags = 0;
    uint32_t seq_number = 0;
    uint32_t ack_number = 0;

    size_t payload_length = 0;
    const uint8_t* payload_data = nullptr;

    bool is_fragmented = false;
    bool is_malformed = false;
};

class PacketParser {
public:
    static bool parse(const RawPacket& raw, ParsedPacket& parsed);
    static bool validate(const ParsedPacket& parsed);
    static std::string_view classifyTransport(uint8_t protocol);

    static std::string macToString(const uint8_t* mac);
    static std::string ipToString(uint32_t ip);
    static std::string protocolToString(uint8_t protocol);
    static std::string tcpFlagsToString(uint8_t flags);

private:
    static bool parseEthernet(const uint8_t* data, size_t len, ParsedPacket& parsed, size_t& offset);
    static bool parseIPv4(const uint8_t* data, size_t len, ParsedPacket& parsed, size_t& offset);
    static bool parseIPv6(const uint8_t* data, size_t len, ParsedPacket& parsed, size_t& offset);
    static bool parseTCP(const uint8_t* data, size_t len, ParsedPacket& parsed, size_t& offset);
    static bool parseUDP(const uint8_t* data, size_t len, ParsedPacket& parsed, size_t& offset);
};

namespace TCPFlags {
    constexpr uint8_t FIN = 0x01;
    constexpr uint8_t SYN = 0x02;
    constexpr uint8_t RST = 0x04;
    constexpr uint8_t PSH = 0x08;
    constexpr uint8_t ACK = 0x10;
    constexpr uint8_t URG = 0x20;
}

namespace Protocol {
    constexpr uint8_t ICMP = 1;
    constexpr uint8_t TCP = 6;
    constexpr uint8_t UDP = 17;
}

namespace EtherType {
    constexpr uint16_t IPv4 = 0x0800;
    constexpr uint16_t IPv6 = 0x86DD;
    constexpr uint16_t ARP  = 0x0806;
}

enum class PacketDirection {
    UNKNOWN = 0,
    INBOUND,
    OUTBOUND
};

}

#endif
