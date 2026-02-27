#ifndef CONNECTION_TRACKER_H
#define CONNECTION_TRACKER_H

#include "types.h"
#include <unordered_map>
#include <shared_mutex>
#include <vector>
#include <chrono>
#include <functional>
#include <list>
#include <atomic>
#include <optional>

namespace DPI {

class ConnectionTracker {
public:
    ConnectionTracker(int fp_id, size_t max_connections = 100000);
    
    Connection* getOrCreateConnection(const FiveTuple& tuple);
    
    Connection* getConnection(const FiveTuple& tuple);
    
    void updateConnection(Connection* conn, size_t packet_size, bool is_outbound);
    
    void classifyConnection(Connection* conn, AppType app, const std::string& sni);
    
    void blockConnection(Connection* conn);
    
    void closeConnection(const FiveTuple& tuple);
    
    size_t cleanupStale(std::chrono::seconds timeout = std::chrono::seconds(300));
    
    std::vector<Connection> getAllConnections() const;
    
    size_t getActiveCount() const;

    void reserve(size_t capacity);

    bool isNearCapacity(double threshold = 0.9) const;

  
    size_t getEvictedCount() const;

  
    size_t getClosedCount() const;
    
    
    struct TrackerStats {
        size_t active_connections;
        size_t total_connections_seen;
        size_t classified_connections;
        size_t blocked_connections;
        size_t evicted_connections;
        size_t closed_connections;
        double  load_factor;
    };
    
    TrackerStats getStats() const;
    
    
    void clear();
    
    
    void forEach(std::function<void(const Connection&)> callback) const;

private:
    int fp_id_;
    size_t max_connections_;

    
    std::unordered_map<FiveTuple, Connection, FiveTupleHash> connections_;

    
    std::list<FiveTuple> lru_list_;
    std::unordered_map<FiveTuple, std::list<FiveTuple>::iterator, FiveTupleHash> lru_index_;

    using Clock = std::chrono::steady_clock;

    
    size_t total_seen_ = 0;
    size_t classified_count_ = 0;
    size_t blocked_count_ = 0;
    size_t evicted_count_ = 0;
    size_t closed_count_ = 0;


    void evictOldest();
    void touchLRU(const FiveTuple& tuple);
    void removeFromLRU(const FiveTuple& tuple);
};


class GlobalConnectionTable {
public:
    GlobalConnectionTable(size_t num_fps);
    

    void registerTracker(int fp_id, ConnectionTracker* tracker);
    
    
    struct GlobalStats {
        size_t total_active_connections;
        size_t total_connections_seen;
        std::unordered_map<AppType, size_t> app_distribution;
        std::vector<std::pair<std::string, size_t>> top_domains;
    };
    
    GlobalStats getGlobalStats() const;

    
    void forEachGlobal(std::function<void(const Connection&)> callback) const;
    
    
    std::string generateReport() const;

private:
    std::vector<ConnectionTracker*> trackers_;
    mutable std::shared_mutex mutex_;

    
    mutable std::chrono::steady_clock::time_point last_snapshot_time_;
};

}

#endif
