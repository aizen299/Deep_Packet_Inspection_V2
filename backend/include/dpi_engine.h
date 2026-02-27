#ifndef DPI_ENGINE_H
#define DPI_ENGINE_H

#include "types.h"
#include "pcap_reader.h"
#include "packet_parser.h"
#include "load_balancer.h"
#include "fast_path.h"
#include "rule_manager.h"
#include "connection_tracker.h"
#include <memory>
#include <thread>
#include <atomic>
#include <fstream>
#include <mutex>
#include <chrono>

namespace DPI {

class DPIEngine {
public:
    struct Config {
        int num_load_balancers = 2;
        int fps_per_lb = 2;
        size_t queue_size = 10000;
        size_t max_connections_per_fp = 100000;
        size_t cleanup_interval_seconds = 30;
        std::string rules_file;
        bool verbose = false;
        bool enable_periodic_cleanup = true;
        bool enable_auto_scaling_hint = false;
    };
    
    DPIEngine(const Config& config);
    ~DPIEngine();
    
    bool initialize();
    
    bool processFile(const std::string& input_file, 
                     const std::string& output_file);
    
    void start();
    
    void stop();
    
    void waitForCompletion();
    
    void restart();
    void resetStats();
    
    void blockIP(const std::string& ip);
    
    void unblockIP(const std::string& ip);
    
    void blockApp(AppType app);
    void blockApp(const std::string& app_name);
    
    void unblockApp(AppType app);
    void unblockApp(const std::string& app_name);
    
    void blockDomain(const std::string& domain);
    
    void unblockDomain(const std::string& domain);
    
    bool loadRules(const std::string& filename);
    
    bool saveRules(const std::string& filename);
    
    std::string generateReport() const;
    
    std::string generateClassificationReport() const;
    
    const DPIStats& getStats() const;
    
    void printStatus() const;
    
    std::string generatePerformanceReport() const;
    
    RuleManager& getRuleManager() { return *rule_manager_; }
    const Config& getConfig() const { return config_; }
    bool isRunning() const { return running_; }

private:
    Config config_;
    
    std::unique_ptr<RuleManager> rule_manager_;
    std::unique_ptr<GlobalConnectionTable> global_conn_table_;
    std::chrono::steady_clock::time_point engine_start_time_;
    
    std::unique_ptr<FPManager> fp_manager_;
    std::unique_ptr<LBManager> lb_manager_;
    
    ThreadSafeQueue<PacketJob> output_queue_;
    std::thread output_thread_;
    std::ofstream output_file_;
    std::mutex output_mutex_;
    
    DPIStats stats_;
    std::atomic<uint64_t> total_packets_processed_{0};
    std::atomic<uint64_t> total_packets_forwarded_{0};
    std::atomic<uint64_t> total_packets_blocked_{0};
    
    std::atomic<bool> running_{false};
    std::atomic<bool> processing_complete_{false};
    std::atomic<bool> initialized_{false};
    
    std::thread reader_thread_;
    
    void outputThreadFunc();
    void handleOutput(const PacketJob& job, PacketAction action);
    
    bool writeOutputHeader(const PacketAnalyzer::PcapGlobalHeader& header);
    
    void writeOutputPacket(const PacketJob& job);
    
    void readerThreadFunc(const std::string& input_file);
    
    void periodicCleanupLoop();
    std::thread cleanup_thread_;
    
    PacketJob createPacketJob(const PacketAnalyzer::RawPacket& raw,
                               const PacketAnalyzer::ParsedPacket& parsed,
                               uint32_t packet_id);
};

}

#endif
