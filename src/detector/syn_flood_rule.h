#pragma once
// FR-3.2: SYN Flood Detection.
// Counts TCP SYN packets that have not been answered by an ACK, per (source -> destination)
// pair. A SYN adds one to the counter, an ACK from the same pair takes one away.
// An alert is raised when unanswered SYNs exceed `synPpsLimit` per second (default 500).

#include <cstddef>
#include <string>
#include <unordered_map>

#include "detection_types.h"
#include "sliding_window_queue.h"

namespace netvanguard {

class SynFloodRule : public DetectionRule {
public:
    explicit SynFloodRule(double synPpsLimit = 500.0, double windowSeconds = 1.0);

    std::optional<Alert> evaluate(const Packet& packet) override;

    void setThreshold(double synPpsLimit);  // configurable (FR-5.1: syn_flood_pps)
    void setWindow(double windowSeconds);   // clears the current state
    void reset();
    std::size_t trackedPairs() const { return pairs_.size(); }

private:
    struct PairState {
        explicit PairState(double window) : pending(window), earlyAcks(window) {}
        SlidingWindowQueue pending;    // SYNs still waiting for their ACK
        SlidingWindowQueue earlyAcks;  // ACKs that arrived before their SYN (out-of-order capture)
        double latest = 0.0;
        bool inAlert = false;
    };

    void evictIdle();

    double limit_;
    double window_;
    double latestSeen_ = 0.0;
    unsigned long processed_ = 0;
    std::unordered_map<std::string, PairState> pairs_;
};

}  // namespace netvanguard
