#ifndef FAST_PATH_H
#define FAST_PATH_H

#include "types.h"
#include "thread_safe_queue.h"
#include "connection_tracker.h"
#include "rule_manager.h"
#include "sni_extractor.h"
#include <thread>
#include <atomic>
#include <memory>
#include <functional>
#include <unordered_map>
#include <string>

namespace DPI {

using PacketOutputCallback = std::function<void(const PacketJob&, PacketAction)>;

class FastPathProcessor {
public:
    FastPathProcessor(int fp_id,
                      RuleManager* rule_manager,
                      PacketOutputCallback output_callback,
                      bool silent);
    
    ~FastPathProcessor();
    
    void start();
    
    void stop();
    
    void pause();
    void resume();
    bool isPaused() const { return paused_; }
    
    ThreadSafeQueue<PacketJob>& getInputQueue() { return input_queue_; }
    
    ConnectionTracker& getConnectionTracker() { return conn_tracker_; }
    
    struct FPStats {
        uint64_t packets_processed;
        uint64_t packets_forwarded;
        uint64_t packets_dropped;
        uint64_t connections_tracked;
        uint64_t sni_extractions;
        uint64_t classification_hits;
        uint64_t current_queue_depth;
        uint64_t max_queue_depth;
        double   drop_ratio;
    };
    
    FPStats getStats() const;

    std::unordered_map<std::string, uint64_t> getApplicationStats() const;
    
    int getId() const { return fp_id_; }
    
    bool isRunning() const { return running_; }

private:
    int fp_id_;
    
    ThreadSafeQueue<PacketJob> input_queue_;
    
    ConnectionTracker conn_tracker_;
    
    RuleManager* rule_manager_;
    
    PacketOutputCallback output_callback_;
    
    bool silent_;
    
    std::atomic<uint64_t> packets_processed_{0};
    std::atomic<uint64_t> packets_forwarded_{0};
    std::atomic<uint64_t> packets_dropped_{0};
    std::atomic<uint64_t> sni_extractions_{0};
    std::atomic<uint64_t> classification_hits_{0};
    std::atomic<uint64_t> max_queue_depth_{0};
    
    std::atomic<bool> running_{false};
    std::atomic<bool> paused_{false};
    std::thread thread_;
    
    void run();
    
    PacketAction processPacket(PacketJob& job);
    
    void inspectPayload(PacketJob& job, Connection* conn);
    
    bool tryExtractSNI(const PacketJob& job, Connection* conn);
    
    bool tryExtractHTTPHost(const PacketJob& job, Connection* conn);
    
    PacketAction checkRules(const PacketJob& job, Connection* conn);
    
    void updateTCPState(Connection* conn, uint8_t tcp_flags);
    
    void updateQueueMetrics();
};

class FPManager {
public:
    FPManager(int num_fps,
              RuleManager* rule_manager,
              PacketOutputCallback output_callback,
              bool silent);
    
    ~FPManager();
    
    void startAll();
    
    void stopAll();
    
    FastPathProcessor& getFP(int id) { return *fps_[id]; }
    
    ThreadSafeQueue<PacketJob>& getFPQueue(int id) { return fps_[id]->getInputQueue(); }
    
    std::vector<ThreadSafeQueue<PacketJob>*> getQueuePtrs() {
        std::vector<ThreadSafeQueue<PacketJob>*> ptrs;
        for (auto& fp : fps_) {
            ptrs.push_back(&fp->getInputQueue());
        }
        return ptrs;
    }
    
    int getNumFPs() const { return fps_.size(); }
    
    struct AggregatedStats {
        uint64_t total_processed;
        uint64_t total_forwarded;
        uint64_t total_dropped;
        uint64_t total_connections;
        uint64_t total_max_queue_depth;
        double   overall_drop_ratio;
    };
    
    AggregatedStats getAggregatedStats() const;

    std::unordered_map<std::string, uint64_t> getApplicationStats() const;
    
    std::string generateClassificationReport() const;
    
    std::string generatePerformanceReport() const;

private:
    std::vector<std::unique_ptr<FastPathProcessor>> fps_;
    bool silent_;
};

}

#endif
