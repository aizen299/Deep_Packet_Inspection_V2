#include "packet_parser.h"
#include "platform.h"
#include <sstream>
#include <iomanip>
#include <cstring>

using PortableNet::netToHost16;
using PortableNet::netToHost32;

#define ntohs(x) netToHost16(x)
#define ntohl(x) netToHost32(x)

namespace PacketAnalyzer {

static inline bool boundsCheck(size_t offset, size_t required, size_t total) {
    return offset <= total && required <= total - offset;
}

bool PacketParser::parse(const RawPacket& raw, ParsedPacket& parsed) {
    parsed = ParsedPacket{};
    parsed.timestamp_sec = raw.header.ts_sec;
    parsed.timestamp_usec = raw.header.ts_usec;

    const uint8_t* data = raw.payload();
    size_t len = raw.size();
    if (!data || len == 0) return false;

    size_t offset = 0;

    if (!parseEthernet(data, len, parsed, offset)) {
        parsed.is_malformed = true;
        return false;
    }

    if (parsed.ether_type == EtherType::IPv4) {
        if (!parseIPv4(data, len, parsed, offset)) {
            parsed.is_malformed = true;
            return false;
        }
    } else if (parsed.ether_type == EtherType::IPv6) {
        if (!parseIPv6(data, len, parsed, offset)) {
            parsed.is_malformed = true;
            return false;
        }
    }

    if (parsed.is_fragmented) {
        if (offset < len) {
            parsed.payload_length = len - offset;
            parsed.payload_data = data + offset;
        }
        return true;
    }

    if (parsed.protocol == Protocol::TCP) {
        if (!parseTCP(data, len, parsed, offset)) {
            parsed.is_malformed = true;
            return false;
        }
    } else if (parsed.protocol == Protocol::UDP) {
        if (!parseUDP(data, len, parsed, offset)) {
            parsed.is_malformed = true;
            return false;
        }
    }

    if (offset < len) {
        parsed.payload_length = len - offset;
        parsed.payload_data = data + offset;
    }

    return true;
}

bool PacketParser::parseEthernet(const uint8_t* data, size_t len,
                                  ParsedPacket& parsed, size_t& offset) {
    constexpr size_t ETH_LEN = 14;
    if (!boundsCheck(offset, ETH_LEN, len)) return false;

    parsed.dest_mac = macToString(data + offset);
    parsed.src_mac  = macToString(data + offset + 6);

    uint16_t type;
    std::memcpy(&type, data + offset + 12, sizeof(uint16_t));
    parsed.ether_type = ntohs(type);

    offset += ETH_LEN;
    return true;
}

bool PacketParser::parseIPv4(const uint8_t* data, size_t len,
                              ParsedPacket& parsed, size_t& offset) {
    constexpr size_t MIN_LEN = 20;
    if (!boundsCheck(offset, MIN_LEN, len)) return false;

    const uint8_t* ip = data + offset;
    uint8_t version = (ip[0] >> 4) & 0x0F;
    uint8_t ihl = ip[0] & 0x0F;

    if (version != 4) return false;

    size_t header_len = ihl * 4;
    if (header_len < MIN_LEN || !boundsCheck(offset, header_len, len)) return false;

    uint16_t flags_frag;
    std::memcpy(&flags_frag, ip + 6, sizeof(uint16_t));
    flags_frag = ntohs(flags_frag);
    bool mf = flags_frag & 0x2000;
    bool has_offset = (flags_frag & 0x1FFF) != 0;
    if (mf || has_offset) parsed.is_fragmented = true;

    parsed.has_ip = true;
    parsed.has_ipv4 = true;
    parsed.ip_version = 4;
    parsed.ttl = ip[8];
    parsed.protocol = ip[9];

    uint32_t src, dst;
    std::memcpy(&src, ip + 12, 4);
    std::memcpy(&dst, ip + 16, 4);

    parsed.src_ip = ipToString(src);
    parsed.dest_ip = ipToString(dst);

    offset += header_len;
    return true;
}

bool PacketParser::parseIPv6(const uint8_t* data, size_t len,
                              ParsedPacket& parsed, size_t& offset) {
    constexpr size_t IPV6_LEN = 40;
    if (!boundsCheck(offset, IPV6_LEN, len)) return false;

    const uint8_t* ip = data + offset;

    parsed.has_ip = true;
    parsed.has_ipv6 = true;
    parsed.ip_version = 6;
    parsed.protocol = ip[6];
    parsed.ttl = ip[7];

    std::ostringstream src, dst;
    for (int i = 0; i < 16; i += 2) {
        uint16_t part;
        std::memcpy(&part, ip + 8 + i, 2);
        part = ntohs(part);
        src << std::hex << part;
        if (i < 14) src << ":";
    }
    for (int i = 0; i < 16; i += 2) {
        uint16_t part;
        std::memcpy(&part, ip + 24 + i, 2);
        part = ntohs(part);
        dst << std::hex << part;
        if (i < 14) dst << ":";
    }

    parsed.src_ip = src.str();
    parsed.dest_ip = dst.str();

    if (parsed.protocol == 44) parsed.is_fragmented = true;

    offset += IPV6_LEN;
    return true;
}

bool PacketParser::parseTCP(const uint8_t* data, size_t len,
                             ParsedPacket& parsed, size_t& offset) {
    constexpr size_t MIN_LEN = 20;
    if (!boundsCheck(offset, MIN_LEN, len)) return false;

    const uint8_t* tcp = data + offset;

    uint16_t sp, dp;
    uint32_t seq, ack;

    std::memcpy(&sp, tcp, 2);
    std::memcpy(&dp, tcp + 2, 2);
    std::memcpy(&seq, tcp + 4, 4);
    std::memcpy(&ack, tcp + 8, 4);

    parsed.src_port = ntohs(sp);
    parsed.dest_port = ntohs(dp);
    parsed.seq_number = ntohl(seq);
    parsed.ack_number = ntohl(ack);

    uint8_t data_offset = (tcp[12] >> 4) & 0x0F;
    size_t header_len = data_offset * 4;
    if (header_len < MIN_LEN || !boundsCheck(offset, header_len, len)) return false;

    parsed.tcp_flags = tcp[13];
    parsed.has_tcp = true;

    offset += header_len;
    return true;
}

bool PacketParser::parseUDP(const uint8_t* data, size_t len,
                             ParsedPacket& parsed, size_t& offset) {
    constexpr size_t UDP_LEN = 8;
    if (!boundsCheck(offset, UDP_LEN, len)) return false;

    const uint8_t* udp = data + offset;

    uint16_t sp, dp;
    std::memcpy(&sp, udp, 2);
    std::memcpy(&dp, udp + 2, 2);

    parsed.src_port = ntohs(sp);
    parsed.dest_port = ntohs(dp);
    parsed.has_udp = true;

    offset += UDP_LEN;
    return true;
}

std::string PacketParser::macToString(const uint8_t* mac) {
    std::ostringstream ss;
    ss << std::hex << std::setfill('0');
    for (int i = 0; i < 6; i++) {
        if (i) ss << ":";
        ss << std::setw(2) << static_cast<int>(mac[i]);
    }
    return ss.str();
}

std::string PacketParser::ipToString(uint32_t ip) {
    std::ostringstream ss;
    ss << ((ip >> 0) & 0xFF) << "."
       << ((ip >> 8) & 0xFF) << "."
       << ((ip >> 16) & 0xFF) << "."
       << ((ip >> 24) & 0xFF);
    return ss.str();
}

std::string PacketParser::protocolToString(uint8_t protocol) {
    switch (protocol) {
        case Protocol::ICMP: return "ICMP";
        case Protocol::TCP:  return "TCP";
        case Protocol::UDP:  return "UDP";
        default: return "Unknown(" + std::to_string(protocol) + ")";
    }
}

std::string PacketParser::tcpFlagsToString(uint8_t flags) {
    std::string result;
    if (flags & TCPFlags::SYN) result += "SYN ";
    if (flags & TCPFlags::ACK) result += "ACK ";
    if (flags & TCPFlags::FIN) result += "FIN ";
    if (flags & TCPFlags::RST) result += "RST ";
    if (flags & TCPFlags::PSH) result += "PSH ";
    if (flags & TCPFlags::URG) result += "URG ";
    if (!result.empty()) result.pop_back();
    return result.empty() ? "none" : result;
}

} 
