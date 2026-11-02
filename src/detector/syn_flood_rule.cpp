#include "syn_flood_rule.h"

#include <algorithm>
#include <cstdio>

namespace netvanguard {

namespace {
constexpr unsigned long kEvictEvery = 4096;  // how often idle pairs are cleaned up
}

SynFloodRule::SynFloodRule(double synPpsLimit, double windowSeconds)
    : limit_(synPpsLimit), window_(windowSeconds) {}

void SynFloodRule::setThreshold(double synPpsLimit) { limit_ = synPpsLimit; }

void SynFloodRule::setWindow(double windowSeconds) {
    window_ = windowSeconds;
    pairs_.clear();
}

void SynFloodRule::reset() {
    pairs_.clear();
    latestSeen_ = 0.0;
    processed_ = 0;
}

std::optional<Alert> SynFloodRule::evaluate(const Packet& p) {
    if (p.protocol != Protocol::TCP) return std::nullopt;

    const bool syn = (p.tcpFlags & TCP_SYN) != 0;
    const bool ack = (p.tcpFlags & TCP_ACK) != 0;
    if (syn && ack) return std::nullopt;   // SYN-ACK is the server's reply, not a client SYN
    if (!syn && !ack) return std::nullopt;  // other TCP packets do not matter here

    latestSeen_ = std::max(latestSeen_, p.timestamp);
    if (++processed_ % kEvictEvery == 0) evictIdle();  // keeps memory bounded

    const std::string key = p.srcIp + ">" + p.destIp;
    auto it = pairs_.find(key);
    if (it == pairs_.end()) it = pairs_.emplace(key, PairState(window_)).first;
    PairState& st = it->second;

    st.latest = std::max(st.latest, p.timestamp);
    st.pending.purgeExpired(st.latest);
    st.earlyAcks.purgeExpired(st.latest);

    if (syn) {
        // If its ACK already arrived (out-of-order capture), the handshake is complete.
        if (!st.earlyAcks.popOldest()) st.pending.push(p.timestamp);
    } else {
        // A plain ACK completes the oldest waiting handshake. If none is waiting, remember
        // the ACK for a moment in case its SYN shows up late.
        if (!st.pending.popOldest()) st.earlyAcks.push(p.timestamp);
    }
    st.pending.purgeExpired(st.latest);

    const double rate = st.pending.rate();  // unanswered SYNs per second

    if (rate > limit_) {
        if (st.inAlert) return std::nullopt;  // one alert per attack, not one per packet
        st.inAlert = true;

        char msg[200];
        std::snprintf(msg, sizeof msg,
                      "Possible SYN flood: %.0f unanswered SYN/s from %s to %s (limit %.0f/s)",
                      rate, p.srcIp.c_str(), p.destIp.c_str(), limit_);

        Alert a;
        a.timestamp = p.timestamp;  // from the packet header (business rule)
        a.ruleId = "SYN_FLOOD";
        a.srcIp = p.srcIp;
        a.destIp = p.destIp;
        a.severity = "HIGH";
        a.message = msg;
        return a;
    }

    // Re-arm once the rate has clearly dropped, so the alert does not flap at the limit.
    if (rate < limit_ / 2.0) st.inAlert = false;
    return std::nullopt;
}

void SynFloodRule::evictIdle() {
    for (auto it = pairs_.begin(); it != pairs_.end();) {
        it->second.pending.purgeExpired(latestSeen_);
        it->second.earlyAcks.purgeExpired(latestSeen_);
        if (it->second.pending.empty() && it->second.earlyAcks.empty())
            it = pairs_.erase(it);
        else
            ++it;
    }
}

}  // namespace netvanguard
