#ifndef PCAP_READER_H
#define PCAP_READER_H

#include <cstdint>
#include <string>
#include <vector>
#include <fstream>
#include <optional>
#include <limits>

namespace PacketAnalyzer {

struct PcapGlobalHeader {
    uint32_t magic_number;
    uint16_t version_major;
    uint16_t version_minor;
    int32_t  thiszone;
    uint32_t sigfigs;
    uint32_t snaplen;
    uint32_t network;
};

struct PcapPacketHeader {
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint32_t incl_len;
    uint32_t orig_len;
};

struct RawPacket {
    PcapPacketHeader header;
    std::vector<uint8_t> data;

    const uint8_t* payload() const {
        return data.empty() ? nullptr : data.data();
    }

    size_t size() const {
        return data.size();
    }
};

class PcapReader {
public:
    explicit PcapReader(bool silent = false) : silent_(silent) {}
    ~PcapReader();

    bool open(const std::string& filename);
    
    void close();
    
    bool readNextPacket(RawPacket& packet);
    bool validateGlobalHeader() const;
    bool validatePacketHeader(const PcapPacketHeader& header) const;
    void enableStrictMode(bool enabled) { strict_mode_ = enabled; }
    
    const PcapGlobalHeader& getGlobalHeader() const { return global_header_; }
    
    bool isOpen() const { return file_.is_open(); }
    
    bool needsByteSwap() const { return needs_byte_swap_; }

private:
    std::ifstream file_;
    PcapGlobalHeader global_header_;
    bool needs_byte_swap_ = false;
    bool strict_mode_ = true;
    uint64_t file_size_ = 0;
    uint64_t bytes_read_ = 0;
    bool silent_ = false;
    
    uint16_t maybeSwap16(uint16_t value) const;
    uint32_t maybeSwap32(uint32_t value) const;
    bool safeRead(char* buffer, std::streamsize size);
};

}

#endif
