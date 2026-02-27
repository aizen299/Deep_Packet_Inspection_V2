#ifndef LOAD_BALANCER_H
#define LOAD_BALANCER_H

#include "types.h"
#include "thread_safe_queue.h"
#include <thread>
#include <vector>
#include <atomic>
#include <memory>

namespace DPI {

class LoadBalancer {
public:
    LoadBalancer(int lb_id, 
                 std::vector<ThreadSafeQueue<PacketJob>*> fp_queues,
                 int fp_start_id);
    
    ~LoadBalancer();
    
    void start();
    
    void stop();
    
    void pause();
    void resume();
    bool isPaused() const { return paused_; }
    
    ThreadSafeQueue<PacketJob>& getInputQueue() { return input_queue_; }
    
    struct LBStats {
        uint64_t packets_received;
        uint64_t packets_dispatched;
        uint64_t current_queue_depth;
        uint64_t max_queue_depth;
        std::vector<uint64_t> per_fp_packets;
        double dispatch_efficiency;
    };
    
    LBStats getStats() const;
    
    int getId() const { return lb_id_; }
    
    bool isRunning() const { return running_; }

private:
    int lb_id_;
    int fp_start_id_;
    int num_fps_;
    
    ThreadSafeQueue<PacketJob> input_queue_;
    
    std::vector<ThreadSafeQueue<PacketJob>*> fp_queues_;
    
    std::atomic<uint64_t> packets_received_{0};
    std::atomic<uint64_t> packets_dispatched_{0};
    std::atomic<uint64_t> max_queue_depth_{0};
    std::vector<uint64_t> per_fp_counts_;
    
    std::atomic<bool> running_{false};
    std::atomic<bool> paused_{false};
    std::thread thread_;
    
    void run();
    
    int selectFP(const FiveTuple& tuple);
    
    void updateQueueMetrics();
};

class LBManager {
public:
    LBManager(int num_lbs, int fps_per_lb,
              std::vector<ThreadSafeQueue<PacketJob>*> fp_queues);
    
    ~LBManager();
    
    void startAll();
    
    void stopAll();
    
    LoadBalancer& getLBForPacket(const FiveTuple& tuple);
    
    LoadBalancer& getLB(int id) { return *lbs_[id]; }
    
    int getNumLBs() const { return lbs_.size(); }
    
    struct AggregatedStats {
        uint64_t total_received;
        uint64_t total_dispatched;
        uint64_t total_max_queue_depth;
        double overall_dispatch_efficiency;
    };
    
    AggregatedStats getAggregatedStats() const;
    
    std::string generatePerformanceReport() const;

private:
    std::vector<std::unique_ptr<LoadBalancer>> lbs_;
    int fps_per_lb_;
};

}

#endif
