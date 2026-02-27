#ifndef THREAD_SAFE_QUEUE_H
#define THREAD_SAFE_QUEUE_H

#include <queue>
#include <mutex>
#include <condition_variable>
#include <optional>
#include <chrono>
#include <atomic>

namespace DPI {

template<typename T>
class ThreadSafeQueue {
public:
    explicit ThreadSafeQueue(size_t max_size = 10000)
        : max_size_(max_size) {}

    bool push(T item) {
        std::unique_lock<std::mutex> lock(mutex_);
        not_full_.wait(lock, [this] { return queue_.size() < max_size_ || shutdown_; });
        if (shutdown_) return false;
        queue_.push(std::move(item));
        updateMetricsOnPush();
        not_empty_.notify_one();
        return true;
    }

    bool tryPush(T item) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (queue_.size() >= max_size_ || shutdown_) return false;
        queue_.push(std::move(item));
        updateMetricsOnPush();
        not_empty_.notify_one();
        return true;
    }

    std::optional<T> pop() {
        std::unique_lock<std::mutex> lock(mutex_);
        not_empty_.wait(lock, [this] { return !queue_.empty() || shutdown_; });
        if (queue_.empty()) return std::nullopt;
        T item = std::move(queue_.front());
        queue_.pop();
        total_pops_++;
        not_full_.notify_one();
        return item;
    }

    std::optional<T> popWithTimeout(std::chrono::milliseconds timeout) {
        std::unique_lock<std::mutex> lock(mutex_);
        if (!not_empty_.wait_for(lock, timeout, [this] { return !queue_.empty() || shutdown_; }))
            return std::nullopt;
        if (queue_.empty()) return std::nullopt;
        T item = std::move(queue_.front());
        queue_.pop();
        total_pops_++;
        not_full_.notify_one();
        return item;
    }

    bool tryPop(T& out) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (queue_.empty()) return false;
        out = std::move(queue_.front());
        queue_.pop();
        total_pops_++;
        not_full_.notify_one();
        return true;
    }

    void clear() {
        std::lock_guard<std::mutex> lock(mutex_);
        while (!queue_.empty()) queue_.pop();
    }

    bool empty() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return queue_.empty();
    }

    size_t size() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return queue_.size();
    }

    size_t capacity() const {
        return max_size_;
    }

    void shutdown() {
        std::lock_guard<std::mutex> lock(mutex_);
        shutdown_ = true;
        not_empty_.notify_all();
        not_full_.notify_all();
    }

    bool isShutdown() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return shutdown_;
    }

    uint64_t totalPushes() const { return total_pushes_.load(); }
    uint64_t totalPops() const { return total_pops_.load(); }
    size_t maxObservedDepth() const { return max_depth_.load(); }

private:
    void updateMetricsOnPush() {
        total_pushes_++;
        size_t current = queue_.size();
        size_t prev_max = max_depth_.load();
        while (current > prev_max &&
               !max_depth_.compare_exchange_weak(prev_max, current)) {}
    }

    std::queue<T> queue_;
    mutable std::mutex mutex_;
    std::condition_variable not_empty_;
    std::condition_variable not_full_;
    size_t max_size_;
    bool shutdown_ = false;

    std::atomic<uint64_t> total_pushes_{0};
    std::atomic<uint64_t> total_pops_{0};
    std::atomic<size_t> max_depth_{0};
};

}

#endif
