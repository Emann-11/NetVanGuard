#pragma once
// TEMPORARY shared types, written from the SRS (FR-1.2 packet fields, FR-4.1 alert fields).
// If dev already has Packet / Alert / DetectionRule from a teammate, delete this file
// and change the #include lines in the rule files to use theirs.

#include <cstdint>
#include <optional>
#include <string>

namespace netvanguard {

enum class Protocol { Other, TCP, UDP, ICMP };

// TCP flag bits, as they appear in the TCP header.
constexpr std::uint8_t TCP_FIN = 0x01;
constexpr std::uint8_t TCP_SYN = 0x02;
constexpr std::uint8_t TCP_RST = 0x04;
constexpr std::uint8_t TCP_ACK = 0x10;

// ICMP message types we care about.
constexpr std::uint8_t ICMP_ECHO_REPLY = 0;
constexpr std::uint8_t ICMP_ECHO_REQUEST = 8;

struct Packet {
    std::string srcIp;
    std::string destIp;
    std::uint16_t srcPort = 0;
    std::uint16_t destPort = 0;
    Protocol protocol = Protocol::Other;
    std::uint8_t tcpFlags = 0;
    std::uint8_t icmpType = 0;
    std::uint8_t icmpCode = 0;
    std::uint32_t payloadLen = 0;
    double timestamp = 0.0;  // seconds, taken from the packet header (not the computer clock)
};

struct Alert {
    double timestamp = 0.0;
    std::string ruleId;
    std::string srcIp;
    std::string destIp;
    std::string severity;
    std::string message;
};

// Base class for every detection rule (see the class diagram: DetectionRule).
class DetectionRule {
public:
    virtual ~DetectionRule() = default;
    // Returns an Alert when this packet pushes the rule over its threshold.
    virtual std::optional<Alert> evaluate(const Packet& packet) = 0;
};

}  // namespace netvanguard
