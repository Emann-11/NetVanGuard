// Unit tests for SynFloodRule (FR-3.2) and PingFloodRule (FR-3.4).
// No test framework needed: build and run with the command in the README / PR description.

#include <iostream>
#include <string>

#include "ping_flood_rule.h"
#include "syn_flood_rule.h"

using namespace netvanguard;

static int g_checks = 0;
static int g_failures = 0;

#define CHECK(cond)                                                              \
    do {                                                                         \
        ++g_checks;                                                              \
        if (!(cond)) {                                                           \
            ++g_failures;                                                        \
            std::cerr << "  FAILED (line " << __LINE__ << "): " #cond << "\n";   \
        }                                                                        \
    } while (0)

// ---------- helpers that build fake packets ----------

static Packet tcp(const std::string& src, const std::string& dst, std::uint8_t flags, double t) {
    Packet p;
    p.srcIp = src;
    p.destIp = dst;
    p.protocol = Protocol::TCP;
    p.tcpFlags = flags;
    p.timestamp = t;
    return p;
}

static Packet icmp(const std::string& src, const std::string& dst, std::uint8_t type, double t) {
    Packet p;
    p.srcIp = src;
    p.destIp = dst;
    p.protocol = Protocol::ICMP;
    p.icmpType = type;
    p.timestamp = t;
    return p;
}

// ---------- SYN flood tests ----------

static void syn_below_threshold_no_alert() {
    SynFloodRule rule;  // limit 500 per second
    int alerts = 0;
    for (int i = 0; i < 500; ++i)
        if (rule.evaluate(tcp("10.0.0.1", "10.0.0.5", TCP_SYN, i * 0.001))) ++alerts;
    CHECK(alerts == 0);
}

static void syn_above_threshold_raises_one_alert() {
    SynFloodRule rule;
    int alerts = 0;
    std::optional<Alert> first;
    int firstIndex = -1;
    for (int i = 0; i < 600; ++i) {
        auto a = rule.evaluate(tcp("10.0.0.1", "10.0.0.5", TCP_SYN, i * 0.001));
        if (a) {
            ++alerts;
            if (!first) {
                first = a;
                firstIndex = i;
            }
        }
    }
    CHECK(alerts == 1);       // one alert per attack, not one per packet
    CHECK(firstIndex == 500);  // the 501st SYN crosses the limit
    CHECK(first.has_value());
    if (first) {
        CHECK(first->ruleId == "SYN_FLOOD");
        CHECK(first->severity == "HIGH");
        CHECK(first->srcIp == "10.0.0.1");
        CHECK(first->destIp == "10.0.0.5");
        CHECK(first->timestamp == 500 * 0.001);  // taken from the packet, not the clock
        CHECK(!first->message.empty());
    }
}

static void syn_answered_by_ack_never_alerts() {
    SynFloodRule rule;
    int alerts = 0;
    for (int i = 0; i < 600; ++i) {
        double t = i * 0.001;
        if (rule.evaluate(tcp("10.0.0.1", "10.0.0.5", TCP_SYN, t))) ++alerts;
        if (rule.evaluate(tcp("10.0.0.1", "10.0.0.5", TCP_ACK, t + 0.0005))) ++alerts;
    }
    CHECK(alerts == 0);
}

static void syn_ack_before_syn_out_of_order() {
    SynFloodRule rule;
    int alerts = 0;
    for (int i = 0; i < 600; ++i) {
        double t = i * 0.001;
        if (rule.evaluate(tcp("10.0.0.1", "10.0.0.5", TCP_ACK, t))) ++alerts;           // arrives first
        if (rule.evaluate(tcp("10.0.0.1", "10.0.0.5", TCP_SYN, t + 0.0001))) ++alerts;  // arrives late
    }
    CHECK(alerts == 0);
}

static void syn_old_syns_expire() {
    SynFloodRule rule;
    int alerts = 0;
    for (int i = 0; i < 500; ++i)
        if (rule.evaluate(tcp("10.0.0.1", "10.0.0.5", TCP_SYN, i * 0.001))) ++alerts;
    for (int i = 0; i < 500; ++i)  // 10 seconds later: the first batch is outside the window
        if (rule.evaluate(tcp("10.0.0.1", "10.0.0.5", TCP_SYN, 10.0 + i * 0.001))) ++alerts;
    CHECK(alerts == 0);
}

static void syn_pairs_are_counted_separately() {
    SynFloodRule rule;
    int alerts = 0;
    for (int i = 0; i < 300; ++i) {
        if (rule.evaluate(tcp("10.0.0.1", "10.0.0.5", TCP_SYN, i * 0.001))) ++alerts;
        if (rule.evaluate(tcp("10.0.0.2", "10.0.0.5", TCP_SYN, i * 0.001))) ++alerts;
    }
    CHECK(alerts == 0);
}

static void syn_ignores_other_packets() {
    SynFloodRule rule;
    int alerts = 0;
    for (int i = 0; i < 1000; ++i) {
        Packet udp = tcp("10.0.0.1", "10.0.0.5", TCP_SYN, i * 0.0005);
        udp.protocol = Protocol::UDP;  // not TCP
        if (rule.evaluate(udp)) ++alerts;
        if (rule.evaluate(tcp("10.0.0.1", "10.0.0.5", TCP_SYN | TCP_ACK, i * 0.0005))) ++alerts;  // SYN-ACK
        if (rule.evaluate(tcp("10.0.0.1", "10.0.0.5", TCP_FIN, i * 0.0005))) ++alerts;            // no SYN/ACK
    }
    CHECK(alerts == 0);
}

static void syn_alert_rearms_after_attack_ends() {
    SynFloodRule rule;
    int alerts = 0;
    for (int i = 0; i < 600; ++i)
        if (rule.evaluate(tcp("10.0.0.1", "10.0.0.5", TCP_SYN, i * 0.001))) ++alerts;
    CHECK(alerts == 1);
    for (int i = 0; i < 600; ++i)  // second attack after a quiet period
        if (rule.evaluate(tcp("10.0.0.1", "10.0.0.5", TCP_SYN, 10.0 + i * 0.001))) ++alerts;
    CHECK(alerts == 2);
}

static void syn_threshold_is_configurable() {
    SynFloodRule rule(10.0);
    int alerts = 0;
    for (int i = 0; i < 11; ++i)
        if (rule.evaluate(tcp("10.0.0.1", "10.0.0.5", TCP_SYN, i * 0.01))) ++alerts;
    CHECK(alerts == 1);
    rule.reset();
    rule.setThreshold(1000.0);
    alerts = 0;
    for (int i = 0; i < 600; ++i)
        if (rule.evaluate(tcp("10.0.0.1", "10.0.0.5", TCP_SYN, i * 0.001))) ++alerts;
    CHECK(alerts == 0);
}

static void syn_memory_stays_bounded() {
    SynFloodRule rule;
    auto ip = [](const char* prefix, int i) {
        return std::string(prefix) + std::to_string(i / 256) + "." + std::to_string(i % 256) + ".1";
    };
    for (int i = 0; i < 5000; ++i) rule.evaluate(tcp(ip("10.", i), "10.9.9.9", TCP_SYN, 0.0));
    for (int i = 0; i < 5000; ++i) rule.evaluate(tcp(ip("11.", i), "10.9.9.9", TCP_SYN, 100.0));
    CHECK(rule.trackedPairs() <= 5000);  // the first 5000 idle pairs were cleaned up
}

// ---------- ping flood tests ----------

static void ping_below_threshold_no_alert() {
    PingFloodRule rule;  // limit 200 per second
    int alerts = 0;
    for (int i = 0; i < 200; ++i)
        if (rule.evaluate(icmp("10.0.0.1", "10.0.0.5", ICMP_ECHO_REQUEST, i * 0.002))) ++alerts;
    CHECK(alerts == 0);
}

static void ping_above_threshold_raises_one_alert() {
    PingFloodRule rule;
    int alerts = 0;
    std::optional<Alert> first;
    int firstIndex = -1;
    for (int i = 0; i < 300; ++i) {
        auto a = rule.evaluate(icmp("10.0.0.1", "10.0.0.5", ICMP_ECHO_REQUEST, i * 0.002));
        if (a) {
            ++alerts;
            if (!first) {
                first = a;
                firstIndex = i;
            }
        }
    }
    CHECK(alerts == 1);
    CHECK(firstIndex == 200);  // the 201st request crosses the limit
    CHECK(first.has_value());
    if (first) {
        CHECK(first->ruleId == "PING_FLOOD");
        CHECK(first->severity == "HIGH");
        CHECK(first->srcIp == "10.0.0.1");
        CHECK(first->destIp == "10.0.0.5");
        CHECK(first->timestamp == 200 * 0.002);
    }
}

static void ping_echo_replies_are_ignored() {
    PingFloodRule rule;
    int alerts = 0;
    for (int i = 0; i < 1000; ++i)
        if (rule.evaluate(icmp("10.0.0.5", "10.0.0.1", ICMP_ECHO_REPLY, i * 0.0005))) ++alerts;
    CHECK(alerts == 0);
}

static void ping_ignores_non_icmp() {
    PingFloodRule rule;
    int alerts = 0;
    for (int i = 0; i < 1000; ++i) {
        Packet p = icmp("10.0.0.1", "10.0.0.5", ICMP_ECHO_REQUEST, i * 0.0005);
        p.protocol = Protocol::UDP;
        if (rule.evaluate(p)) ++alerts;
    }
    CHECK(alerts == 0);
}

static void ping_targets_are_counted_separately() {
    PingFloodRule rule;
    int alerts = 0;
    for (int i = 0; i < 150; ++i) {
        if (rule.evaluate(icmp("10.0.0.1", "10.0.0.5", ICMP_ECHO_REQUEST, i * 0.002))) ++alerts;
        if (rule.evaluate(icmp("10.0.0.1", "10.0.0.6", ICMP_ECHO_REQUEST, i * 0.002))) ++alerts;
    }
    CHECK(alerts == 0);
}

static void ping_old_requests_expire() {
    PingFloodRule rule;
    int alerts = 0;
    for (int i = 0; i < 150; ++i)
        if (rule.evaluate(icmp("10.0.0.1", "10.0.0.5", ICMP_ECHO_REQUEST, i * 0.002))) ++alerts;
    for (int i = 0; i < 150; ++i)
        if (rule.evaluate(icmp("10.0.0.1", "10.0.0.5", ICMP_ECHO_REQUEST, 10.0 + i * 0.002))) ++alerts;
    CHECK(alerts == 0);
}

static void ping_out_of_order_timestamps_ok() {
    PingFloodRule rule;
    int alerts = 0;
    // every second packet arrives slightly late; the count must still be right
    for (int i = 0; i < 100; ++i) {
        double t = i * 0.004;
        if (rule.evaluate(icmp("10.0.0.1", "10.0.0.5", ICMP_ECHO_REQUEST, t + 0.002))) ++alerts;
        if (rule.evaluate(icmp("10.0.0.1", "10.0.0.5", ICMP_ECHO_REQUEST, t))) ++alerts;
    }
    CHECK(alerts == 0);  // exactly 200 requests in 0.4 s, not above the limit
    if (rule.evaluate(icmp("10.0.0.1", "10.0.0.5", ICMP_ECHO_REQUEST, 0.401))) ++alerts;
    CHECK(alerts == 1);  // the 201st one crosses it
}

static void ping_threshold_is_configurable() {
    PingFloodRule rule(10.0);
    int alerts = 0;
    for (int i = 0; i < 11; ++i)
        if (rule.evaluate(icmp("10.0.0.1", "10.0.0.5", ICMP_ECHO_REQUEST, i * 0.01))) ++alerts;
    CHECK(alerts == 1);
}

static void ping_alert_rearms_after_attack_ends() {
    PingFloodRule rule;
    int alerts = 0;
    for (int i = 0; i < 300; ++i)
        if (rule.evaluate(icmp("10.0.0.1", "10.0.0.5", ICMP_ECHO_REQUEST, i * 0.002))) ++alerts;
    for (int i = 0; i < 300; ++i)
        if (rule.evaluate(icmp("10.0.0.1", "10.0.0.5", ICMP_ECHO_REQUEST, 10.0 + i * 0.002))) ++alerts;
    CHECK(alerts == 2);
}

static void ping_memory_stays_bounded() {
    PingFloodRule rule;
    auto ip = [](const char* prefix, int i) {
        return std::string(prefix) + std::to_string(i / 256) + "." + std::to_string(i % 256) + ".1";
    };
    for (int i = 0; i < 5000; ++i) rule.evaluate(icmp("10.0.0.1", ip("10.", i), ICMP_ECHO_REQUEST, 0.0));
    for (int i = 0; i < 5000; ++i) rule.evaluate(icmp("10.0.0.1", ip("11.", i), ICMP_ECHO_REQUEST, 100.0));
    CHECK(rule.trackedTargets() <= 5000);
}

// ---------- runner ----------

struct TestCase {
    const char* name;
    void (*fn)();
};

int main() {
    const TestCase tests[] = {
        {"syn_below_threshold_no_alert", syn_below_threshold_no_alert},
        {"syn_above_threshold_raises_one_alert", syn_above_threshold_raises_one_alert},
        {"syn_answered_by_ack_never_alerts", syn_answered_by_ack_never_alerts},
        {"syn_ack_before_syn_out_of_order", syn_ack_before_syn_out_of_order},
        {"syn_old_syns_expire", syn_old_syns_expire},
        {"syn_pairs_are_counted_separately", syn_pairs_are_counted_separately},
        {"syn_ignores_other_packets", syn_ignores_other_packets},
        {"syn_alert_rearms_after_attack_ends", syn_alert_rearms_after_attack_ends},
        {"syn_threshold_is_configurable", syn_threshold_is_configurable},
        {"syn_memory_stays_bounded", syn_memory_stays_bounded},
        {"ping_below_threshold_no_alert", ping_below_threshold_no_alert},
        {"ping_above_threshold_raises_one_alert", ping_above_threshold_raises_one_alert},
        {"ping_echo_replies_are_ignored", ping_echo_replies_are_ignored},
        {"ping_ignores_non_icmp", ping_ignores_non_icmp},
        {"ping_targets_are_counted_separately", ping_targets_are_counted_separately},
        {"ping_old_requests_expire", ping_old_requests_expire},
        {"ping_out_of_order_timestamps_ok", ping_out_of_order_timestamps_ok},
        {"ping_threshold_is_configurable", ping_threshold_is_configurable},
        {"ping_alert_rearms_after_attack_ends", ping_alert_rearms_after_attack_ends},
        {"ping_memory_stays_bounded", ping_memory_stays_bounded},
    };

    for (const auto& t : tests) {
        int before = g_failures;
        t.fn();
        std::cout << (g_failures == before ? "[PASS] " : "[FAIL] ") << t.name << "\n";
    }
    std::cout << "\n" << g_checks << " checks, " << g_failures << " failed\n";
    return g_failures == 0 ? 0 : 1;
}
