#include <iostream>
#include "pcap_reader.h"
#include "packet_parser.h"
#include "sni_extractor.h"
#include "types.h"

using namespace PacketAnalyzer;
using namespace DPI;

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <pcap_file>\n";
        return 1;
    }
    
    PcapReader reader;
    if (!reader.open(argv[1])) {
        return 1;
    }
    
    RawPacket raw;
    ParsedPacket parsed;
    int count = 0;
    int tls_count = 0;
    
    std::cout << "Processing packets...\n";
    
    while (reader.readNextPacket(raw)) {
        count++;
        
        if (!PacketParser::parse(raw, parsed)) {
            continue;
        }
        
        if (!parsed.has_ip) continue;
        
        std::cout << "Packet " << count << ": " 
                  << parsed.src_ip << ":" << parsed.src_port
                  << " -> " << parsed.dest_ip << ":" << parsed.dest_port;
        
        if (parsed.has_tcp && parsed.dest_port == 443 &&
            parsed.payload_data != nullptr && parsed.payload_length > 0) {
            auto sni = SNIExtractor::extract(parsed.payload_data, parsed.payload_length);
            if (sni) {
                std::cout << " [SNI: " << *sni << "]";
                tls_count++;
            }
        }
        
        std::cout << "\n";
    }
    
    std::cout << "\nTotal packets: " << count << "\n";
    std::cout << "SNI extracted: " << tls_count << "\n";
    
    reader.close();
    return 0;
}
