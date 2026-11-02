#pragma once
// PLACEHOLDER for FR-2.3 (sliding window rate tracking).
// Keeps the timestamps (in seconds) of events that happened in the last `window` seconds.
// If the team already has its own SlidingWindowQueue on dev, use that one instead.

#include <cstddef>
#include <deque>

namespace netvanguard {

class SlidingWindowQueue {
public:
    explicit SlidingWindowQueue(double windowSeconds = 1.0) : window_(windowSeconds) {}

    // Adds an event. Packets can arrive slightly out of order, so the timestamp is
    // inserted in sorted position. Events older than the window are dropped.
    void push(double timestamp) {
        auto pos = ts_.end();
        while (pos != ts_.begin() && *(pos - 1) > timestamp) --pos;
        ts_.insert(pos, timestamp);
        if (timestamp > latest_) latest_ = timestamp;
        purgeExpired(latest_);
    }

    // Removes events that are older than (now - window).
    void purgeExpired(double now) {
        const double cutoff = now - window_;
        while (!ts_.empty() && ts_.front() < cutoff) ts_.pop_front();
    }

    // Removes the oldest event. Returns false if the queue was empty.
    bool popOldest() {
        if (ts_.empty()) return false;
        ts_.pop_front();
        return true;
    }

    std::size_t count() const { return ts_.size(); }
    bool empty() const { return ts_.empty(); }
    double latest() const { return latest_; }
    double window() const { return window_; }
    // Events per second inside the window.
    double rate() const { return window_ > 0.0 ? static_cast<double>(ts_.size()) / window_ : 0.0; }

private:
    double window_;
    double latest_ = 0.0;
    std::deque<double> ts_;
};

}  // namespace netvanguard
