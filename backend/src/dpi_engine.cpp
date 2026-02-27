#include "dpi_engine.h"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <cstring>
#include <fstream>

namespace DPI {

static void writeJsonReport(const std::string& path, const DPIStats& stats) {
    std::ofstream out(path);
    if (!out.is_open()) return;

    out << "{\n";
    out << "  \"summary\": {\n";
    out << "    \"total_packets\": " << stats.total_packets.load() << ",\n";
    out << "    \"total_bytes\": " << stats.total_bytes.load() << ",\n";
    out << "    \"tcp_packets\": " << stats.tcp_packets.load() << ",\n";
    out << "    \"udp_packets\": " << stats.udp_packets.load() << ",\n";
    out << "    \"forwarded\": " << stats.forwarded_packets.load() << ",\n";
    out << "    \"dropped\": " << stats.dropped_packets.load() << "\n";
    out << "  }\n";
    out << "}\n";
}

DPIEngine::DPIEngine(const Config& config)
    : config_(config), output_queue_(10000) {
    
    std::cout << "\n";
    std::cout << "╔══════════════════════════════════════════════════════════════╗\n";
    std::cout << "║                    DPI ENGINE v1.0                            ║\n";
    std::cout << "║               Deep Packet Inspection System                   ║\n";
    std::cout << "╠══════════════════════════════════════════════════════════════╣\n";
    std::cout << "║ Configuration:                                                ║\n";
    std::cout << "║   Load Balancers:    " << std::setw(3) << config.num_load_balancers << "                                       ║\n";
    std::cout << "║   FPs per LB:        " << std::setw(3) << config.fps_per_lb << "                                       ║\n";
    std::cout << "║   Total FP threads:  " << std::setw(3) << (config.num_load_balancers * config.fps_per_lb) << "                                       ║\n";
    std::cout << "╚══════════════════════════════════════════════════════════════╝\n";
}

DPIEngine::~DPIEngine() {
    stop();
}

bool DPIEngine::initialize() {
    rule_manager_ = std::make_unique<RuleManager>();
    if (!config_.rules_file.empty()) {
        rule_manager_->loadRules(config_.rules_file);
    }
    auto output_cb = [this](const PacketJob& job, PacketAction action) {
        handleOutput(job, action);
    };
    int total_fps = config_.num_load_balancers * config_.fps_per_lb;
    fp_manager_ = std::make_unique<FPManager>(total_fps, rule_manager_.get(), output_cb);
    lb_manager_ = std::make_unique<LBManager>(
        config_.num_load_balancers,
        config_.fps_per_lb,
        fp_manager_->getQueuePtrs()
    );
    global_conn_table_ = std::make_unique<GlobalConnectionTable>(total_fps);
    for (int i = 0; i < total_fps; i++) {
        global_conn_table_->registerTracker(i, &fp_manager_->getFP(i).getConnectionTracker());
    }
    std::cout << "[DPIEngine] Initialized successfully\n";
    return true;
}

void DPIEngine::start() {
    if (running_) return;
    
    running_ = true;
    processing_complete_ = false;
    
    output_thread_ = std::thread(&DPIEngine::outputThreadFunc, this);
    fp_manager_->startAll();
    lb_manager_->startAll();
    std::cout << "[DPIEngine] All threads started\n";
}

void DPIEngine::stop() {
    if (!running_) return;
    
    running_ = false;
    
    if (lb_manager_) {
        lb_manager_->stopAll();
    }
    if (fp_manager_) {
        fp_manager_->stopAll();
    }
    output_queue_.shutdown();
    if (output_thread_.joinable()) {
        output_thread_.join();
    }
    std::cout << "[DPIEngine] All threads stopped\n";
}

void DPIEngine::waitForCompletion() {
    if (reader_thread_.joinable()) {
        reader_thread_.join();
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    processing_complete_ = true;
}

bool DPIEngine::processFile(const std::string& input_file,
                            const std::string& output_file) {
    
    std::cout << "\n[DPIEngine] Processing: " << input_file << "\n";
    std::cout << "[DPIEngine] Output to:  " << output_file << "\n\n";
    
    if (!rule_manager_) {
        if (!initialize()) {
            return false;
        }
    }
    output_file_.open(output_file, std::ios::binary);
    if (!output_file_.is_open()) {
        std::cerr << "[DPIEngine] Error: Cannot open output file\n";
        return false;
    }
    start();
    reader_thread_ = std::thread(&DPIEngine::readerThreadFunc, this, input_file);
    waitForCompletion();
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    stop();
    if (output_file_.is_open()) {
        output_file_.close();
    }
    std::cout << generateReport();
    std::cout << fp_manager_->generateClassificationReport();
    writeJsonReport("stats.json", stats_);
    return true;
}

void DPIEngine::readerThreadFunc(const std::string& input_file) {
    PacketAnalyzer::PcapReader reader;
    
    if (!reader.open(input_file)) {
        std::cerr << "[Reader] Error: Cannot open input file\n";
        return;
    }
    
    writeOutputHeader(reader.getGlobalHeader());
    
    PacketAnalyzer::RawPacket raw;
    PacketAnalyzer::ParsedPacket parsed;
    uint32_t packet_id = 0;
    
    std::cout << "[Reader] Starting packet processing...\n";
    
    while (reader.readNextPacket(raw)) {
        if (!PacketAnalyzer::PacketParser::parse(raw, parsed)) {
            continue;
        }
        if (!parsed.has_ip || (!parsed.has_tcp && !parsed.has_udp)) {
            continue;
        }
        PacketJob job = createPacketJob(raw, parsed, packet_id++);
        stats_.total_packets++;
        stats_.total_bytes += raw.data.size();
        if (parsed.has_tcp) {
            stats_.tcp_packets++;
        } else if (parsed.has_udp) {
            stats_.udp_packets++;
        }
        LoadBalancer& lb = lb_manager_->getLBForPacket(job.tuple);
        lb.getInputQueue().push(std::move(job));
    }
    
    std::cout << "[Reader] Finished reading " << packet_id << " packets\n";
    reader.close();
}

PacketJob DPIEngine::createPacketJob(const PacketAnalyzer::RawPacket& raw,
                                      const PacketAnalyzer::ParsedPacket& parsed,
                                      uint32_t packet_id) {
    PacketJob job;
    job.packet_id = packet_id;
    job.ts_sec = raw.header.ts_sec;
    job.ts_usec = raw.header.ts_usec;
    
    auto parseIP = [](const std::string& ip) -> uint32_t {
        uint32_t result = 0;
        int octet = 0;
        int shift = 0;
        for (char c : ip) {
            if (c == '.') {
                result |= (octet << shift);
                shift += 8;
                octet = 0;
            } else if (c >= '0' && c <= '9') {
                octet = octet * 10 + (c - '0');
            }
        }
        result |= (octet << shift);
        return result;
    };
    job.tuple.src_ip = parseIP(parsed.src_ip);
    job.tuple.dst_ip = parseIP(parsed.dest_ip);
    job.tuple.src_port = parsed.src_port;
    job.tuple.dst_port = parsed.dest_port;
    job.tuple.protocol = parsed.protocol;
    job.tcp_flags = parsed.tcp_flags;
    job.data = raw.data;
    job.eth_offset = 0;
    job.ip_offset = 14;  // Ethernet header is 14 bytes
    if (job.data.size() > 14) {
        uint8_t ip_ihl = job.data[14] & 0x0F;
        size_t ip_header_len = ip_ihl * 4;
        job.transport_offset = 14 + ip_header_len;
        if (parsed.has_tcp && job.data.size() > job.transport_offset) {
            uint8_t tcp_data_offset = (job.data[job.transport_offset + 12] >> 4) & 0x0F;
            size_t tcp_header_len = tcp_data_offset * 4;
            job.payload_offset = job.transport_offset + tcp_header_len;
        } else if (parsed.has_udp) {
            job.payload_offset = job.transport_offset + 8;  // UDP header is 8 bytes
        }
        if (job.payload_offset < job.data.size()) {
            job.payload_length = job.data.size() - job.payload_offset;
            job.payload_data = job.data.data() + job.payload_offset;
        }
    }
    return job;
}

void DPIEngine::outputThreadFunc() {
    while (running_ || !output_queue_.empty()) {
        auto job_opt = output_queue_.popWithTimeout(std::chrono::milliseconds(100));
        
        if (job_opt) {
            writeOutputPacket(*job_opt);
        }
    }
}

void DPIEngine::handleOutput(const PacketJob& job, PacketAction action) {
    if (action == PacketAction::DROP) {
        stats_.dropped_packets++;
        return;
    }
    
    stats_.forwarded_packets++;
    output_queue_.push(job);
}

bool DPIEngine::writeOutputHeader(const PacketAnalyzer::PcapGlobalHeader& header) {
    std::lock_guard<std::mutex> lock(output_mutex_);
    
    if (!output_file_.is_open()) return false;
    
    output_file_.write(reinterpret_cast<const char*>(&header), sizeof(header));
    return output_file_.good();
}

void DPIEngine::writeOutputPacket(const PacketJob& job) {
    std::lock_guard<std::mutex> lock(output_mutex_);
    
    if (!output_file_.is_open()) return;
    
    PacketAnalyzer::PcapPacketHeader pkt_header;
    pkt_header.ts_sec = job.ts_sec;
    pkt_header.ts_usec = job.ts_usec;
    pkt_header.incl_len = job.data.size();
    pkt_header.orig_len = job.data.size();
    output_file_.write(reinterpret_cast<const char*>(&pkt_header), sizeof(pkt_header));
    output_file_.write(reinterpret_cast<const char*>(job.data.data()), job.data.size());
}

void DPIEngine::blockIP(const std::string& ip) {
    if (rule_manager_) {
        rule_manager_->blockIP(ip);
    }
}

void DPIEngine::unblockIP(const std::string& ip) {
    if (rule_manager_) {
        rule_manager_->unblockIP(ip);
    }
}

void DPIEngine::blockApp(AppType app) {
    if (rule_manager_) {
        rule_manager_->blockApp(app);
    }
}

void DPIEngine::blockApp(const std::string& app_name) {
    for (int i = 0; i < static_cast<int>(AppType::APP_COUNT); i++) {
        if (appTypeToString(static_cast<AppType>(i)) == app_name) {
            blockApp(static_cast<AppType>(i));
            return;
        }
    }
    std::cerr << "[DPIEngine] Unknown app: " << app_name << "\n";
}

void DPIEngine::unblockApp(AppType app) {
    if (rule_manager_) {
        rule_manager_->unblockApp(app);
    }
}

void DPIEngine::unblockApp(const std::string& app_name) {
    for (int i = 0; i < static_cast<int>(AppType::APP_COUNT); i++) {
        if (appTypeToString(static_cast<AppType>(i)) == app_name) {
            unblockApp(static_cast<AppType>(i));
            return;
        }
    }
}

void DPIEngine::blockDomain(const std::string& domain) {
    if (rule_manager_) {
        rule_manager_->blockDomain(domain);
    }
}

void DPIEngine::unblockDomain(const std::string& domain) {
    if (rule_manager_) {
        rule_manager_->unblockDomain(domain);
    }
}

bool DPIEngine::loadRules(const std::string& filename) {
    if (rule_manager_) {
        return rule_manager_->loadRules(filename);
    }
    return false;
}

bool DPIEngine::saveRules(const std::string& filename) {
    if (rule_manager_) {
        return rule_manager_->saveRules(filename);
    }
    return false;
}


std::string DPIEngine::generateReport() const {
    std::ostringstream ss;
    
    ss << "\n╔══════════════════════════════════════════════════════════════╗\n";
    ss << "║                    DPI ENGINE STATISTICS                      ║\n";
    ss << "╠══════════════════════════════════════════════════════════════╣\n";
    
    ss << "║ PACKET STATISTICS                                             ║\n";
    ss << "║   Total Packets:      " << std::setw(12) << stats_.total_packets.load() << "                        ║\n";
    ss << "║   Total Bytes:        " << std::setw(12) << stats_.total_bytes.load() << "                        ║\n";
    ss << "║   TCP Packets:        " << std::setw(12) << stats_.tcp_packets.load() << "                        ║\n";
    ss << "║   UDP Packets:        " << std::setw(12) << stats_.udp_packets.load() << "                        ║\n";
    
    ss << "╠══════════════════════════════════════════════════════════════╣\n";
    ss << "║ FILTERING STATISTICS                                          ║\n";
    ss << "║   Forwarded:          " << std::setw(12) << stats_.forwarded_packets.load() << "                        ║\n";
    ss << "║   Dropped/Blocked:    " << std::setw(12) << stats_.dropped_packets.load() << "                        ║\n";
    
    if (stats_.total_packets > 0) {
        double drop_rate = 100.0 * stats_.dropped_packets.load() / stats_.total_packets.load();
        ss << "║   Drop Rate:          " << std::setw(11) << std::fixed << std::setprecision(2) << drop_rate << "%                        ║\n";
    }
    
    if (lb_manager_) {
        auto lb_stats = lb_manager_->getAggregatedStats();
        ss << "╠══════════════════════════════════════════════════════════════╣\n";
        ss << "║ LOAD BALANCER STATISTICS                                      ║\n";
        ss << "║   LB Received:        " << std::setw(12) << lb_stats.total_received << "                        ║\n";
        ss << "║   LB Dispatched:      " << std::setw(12) << lb_stats.total_dispatched << "                        ║\n";
    }
    
    if (fp_manager_) {
        auto fp_stats = fp_manager_->getAggregatedStats();
        ss << "╠══════════════════════════════════════════════════════════════╣\n";
        ss << "║ FAST PATH STATISTICS                                          ║\n";
        ss << "║   FP Processed:       " << std::setw(12) << fp_stats.total_processed << "                        ║\n";
        ss << "║   FP Forwarded:       " << std::setw(12) << fp_stats.total_forwarded << "                        ║\n";
        ss << "║   FP Dropped:         " << std::setw(12) << fp_stats.total_dropped << "                        ║\n";
        ss << "║   Active Connections: " << std::setw(12) << fp_stats.total_connections << "                        ║\n";
    }
    
    if (rule_manager_) {
        auto rule_stats = rule_manager_->getStats();
        ss << "╠══════════════════════════════════════════════════════════════╣\n";
        ss << "║ BLOCKING RULES                                                ║\n";
        ss << "║   Blocked IPs:        " << std::setw(12) << rule_stats.blocked_ips << "                        ║\n";
        ss << "║   Blocked Apps:       " << std::setw(12) << rule_stats.blocked_apps << "                        ║\n";
        ss << "║   Blocked Domains:    " << std::setw(12) << rule_stats.blocked_domains << "                        ║\n";
        ss << "║   Blocked Ports:      " << std::setw(12) << rule_stats.blocked_ports << "                        ║\n";
    }
    
    ss << "╚══════════════════════════════════════════════════════════════╝\n";
    
    return ss.str();
}

std::string DPIEngine::generateClassificationReport() const {
    if (fp_manager_) {
        return fp_manager_->generateClassificationReport();
    }
    return "";
}

const DPIStats& DPIEngine::getStats() const {
    return stats_;
}

void DPIEngine::printStatus() const {
    std::cout << "\n--- Live Status ---\n";
    std::cout << "Packets: " << stats_.total_packets.load()
              << " | Forwarded: " << stats_.forwarded_packets.load()
              << " | Dropped: " << stats_.dropped_packets.load() << "\n";
    
    if (fp_manager_) {
        auto fp_stats = fp_manager_->getAggregatedStats();
        std::cout << "Connections: " << fp_stats.total_connections << "\n";
    }
}

}
