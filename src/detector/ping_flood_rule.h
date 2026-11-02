#pragma once
// FR-3.4: Ping Flood Detection.
// Counts ICMP Echo Requests (type 8) per target IP. An alert is raised when the rate
// exceeds `icmpPpsLimit` packets per second (default 200). Echo Replies (type 0) are ignored.

#include <cstddef>
#include <string>
#include <unordered_map>

#include "detection_types.h"
#include "sliding_window_queue.h"

namespace netvanguard {

class PingFloodRule : public DetectionRule {
public:
    explicit PingFloodRule(double icmpPpsLimit = 200.0, double windowSeconds = 1.0);

    std::optional<Alert> evaluate(const Packet& packet) override;

    void setThreshold(double icmpPpsLimit);  // configurable (FR-5.1)
    void setWindow(double windowSeconds);    // clears the current state
    void reset();
    std::size_t trackedTargets() const { return targets_.size(); }

private:
    struct TargetState {
        explicit TargetState(double window) : requests(window) {}
        SlidingWindowQueue requests;  // Echo Request timestamps for this target
        bool inAlert = false;
    };

    void evictIdle();

    double limit_;
    double window_;
    double latestSeen_ = 0.0;
    unsigned long processed_ = 0;
    std::unordered_map<std::string, TargetState> targets_;
};

}  // namespace netvanguard
