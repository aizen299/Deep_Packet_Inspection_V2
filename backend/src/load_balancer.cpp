#include "load_balancer.h"
#include <iostream>
#include <chrono>

namespace DPI {

LoadBalancer::LoadBalancer(int lb_id,
                           std::vector<ThreadSafeQueue<PacketJob>*> fp_queues,
                           int fp_start_id,
                           bool silent)
    : lb_id_(lb_id),
      fp_start_id_(fp_start_id),
      num_fps_(fp_queues.size()),
      input_queue_(10000),
      fp_queues_(std::move(fp_queues)),
      silent_(silent)
{
    per_fp_counts_.resize(num_fps_);
}

LoadBalancer::~LoadBalancer() {
    stop();
}

void LoadBalancer::start() {
    if (running_) return;
    
    running_ = true;
    thread_ = std::thread(&LoadBalancer::run, this);
    
    if (!silent_) {
        std::cout << "[LB" << lb_id_ << "] Started (serving FP" 
                  << fp_start_id_ << "-FP" << (fp_start_id_ + num_fps_ - 1) << ")\n";
    }
}

void LoadBalancer::stop() {
    if (!running_) return;
    
    running_ = false;
    input_queue_.shutdown();
    
    if (thread_.joinable()) {
        thread_.join();
    }
    
    if (!silent_) {
        std::cout << "[LB" << lb_id_ << "] Stopped\n";
    }
}

void LoadBalancer::run() {
    while (running_) {
        auto job_opt = input_queue_.popWithTimeout(std::chrono::milliseconds(100));
        
        if (!job_opt) {
            continue;
        }
        
        packets_received_++;
        
        if (num_fps_ == 0) {
            continue;
        }

        int fp_index = selectFP(job_opt->tuple);

        if (fp_index < 0 || fp_index >= static_cast<int>(fp_queues_.size()) || !fp_queues_[fp_index]) {
            continue;
        }

        fp_queues_[fp_index]->push(std::move(*job_opt));

        packets_dispatched_++;
        per_fp_counts_[fp_index]++;
    }
}

int LoadBalancer::selectFP(const FiveTuple& tuple) {
    if (num_fps_ == 0) {
        return 0;
    }

    FiveTupleHash hasher;
    size_t hash = hasher(tuple);
    return static_cast<int>(hash % num_fps_);
}

LoadBalancer::LBStats LoadBalancer::getStats() const {
    LBStats stats;
    stats.packets_received = packets_received_.load();
    stats.packets_dispatched = packets_dispatched_.load();
    
    stats.per_fp_packets = per_fp_counts_;
    
    return stats;
}

LBManager::LBManager(int num_lbs, int fps_per_lb,
                     std::vector<ThreadSafeQueue<PacketJob>*> fp_queues,
                     bool silent)
    : fps_per_lb_(fps_per_lb),
      silent_(silent) {
    
    for (int lb_id = 0; lb_id < num_lbs; lb_id++) {
        std::vector<ThreadSafeQueue<PacketJob>*> lb_fp_queues;
        int fp_start = lb_id * fps_per_lb;
        
        for (int i = 0; i < fps_per_lb; i++) {
            int index = fp_start + i;
            if (index < 0 || index >= static_cast<int>(fp_queues.size())) {
                continue;
            }
            lb_fp_queues.push_back(fp_queues[index]);
        }
        
        if (lb_fp_queues.empty()) {
            if (!silent_) {
                std::cerr << "Warning: LB" << lb_id << " has zero FP queues\n";
            }
        }
        
        lbs_.push_back(std::make_unique<LoadBalancer>(lb_id, lb_fp_queues, fp_start, silent_));
    }
    
    if (!silent_) {
        std::cout << "[LBManager] Created " << num_lbs << " load balancers, "
                  << fps_per_lb << " FPs each\n";
    }
}

LBManager::~LBManager() {
    stopAll();
}

void LBManager::startAll() {
    for (auto& lb : lbs_) {
        lb->start();
    }
}

void LBManager::stopAll() {
    for (auto& lb : lbs_) {
        lb->stop();
    }
}

LoadBalancer& LBManager::getLBForPacket(const FiveTuple& tuple) {
    FiveTupleHash hasher;
    size_t hash = hasher(tuple);
    int lb_index = hash % lbs_.size();
    return *lbs_[lb_index];
}

LBManager::AggregatedStats LBManager::getAggregatedStats() const {
    AggregatedStats stats = {0, 0};
    
    for (const auto& lb : lbs_) {
        auto lb_stats = lb->getStats();
        stats.total_received += lb_stats.packets_received;
        stats.total_dispatched += lb_stats.packets_dispatched;
    }
    
    return stats;
}

}
