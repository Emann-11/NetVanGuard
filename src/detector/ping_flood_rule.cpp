#include "ping_flood_rule.h"

#include <algorithm>
#include <cstdio>

namespace netvanguard {

namespace {
constexpr unsigned long kEvictEvery = 4096;
}

PingFloodRule::PingFloodRule(double icmpPpsLimit, double windowSeconds)
    : limit_(icmpPpsLimit), window_(windowSeconds) {}

void PingFloodRule::setThreshold(double icmpPpsLimit) { limit_ = icmpPpsLimit; }

void PingFloodRule::setWindow(double windowSeconds) {
    window_ = windowSeconds;
    targets_.clear();
}

void PingFloodRule::reset() {
    targets_.clear();
    latestSeen_ = 0.0;
    processed_ = 0;
}

std::optional<Alert> PingFloodRule::evaluate(const Packet& p) {
    // Only Echo Requests count. Echo Replies (type 0) and other ICMP types are ignored.
    if (p.protocol != Protocol::ICMP || p.icmpType != ICMP_ECHO_REQUEST) return std::nullopt;

    latestSeen_ = std::max(latestSeen_, p.timestamp);
    if (++processed_ % kEvictEvery == 0) evictIdle();

    auto it = targets_.find(p.destIp);
    if (it == targets_.end()) it = targets_.emplace(p.destIp, TargetState(window_)).first;
    TargetState& st = it->second;

    st.requests.push(p.timestamp);  // also drops requests older than the window
    const double rate = st.requests.rate();

    if (rate > limit_) {
        if (st.inAlert) return std::nullopt;
        st.inAlert = true;

        char msg[200];
        std::snprintf(msg, sizeof msg,
                      "Possible ICMP ping flood: %.0f Echo Requests/s to %s (limit %.0f/s)",
                      rate, p.destIp.c_str(), limit_);

        Alert a;
        a.timestamp = p.timestamp;  // from the packet header (business rule)
        a.ruleId = "PING_FLOOD";
        a.srcIp = p.srcIp;
        a.destIp = p.destIp;
        a.severity = "HIGH";
        a.message = msg;
        return a;
    }

    if (rate < limit_ / 2.0) st.inAlert = false;
    return std::nullopt;
}

void PingFloodRule::evictIdle() {
    for (auto it = targets_.begin(); it != targets_.end();) {
        it->second.requests.purgeExpired(latestSeen_);
        if (it->second.requests.empty())
            it = targets_.erase(it);
        else
            ++it;
    }
}

}  // namespace netvanguard
