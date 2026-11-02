#pragma once
#include <string>
#include <iostream>
#include <unordered_map>
#include <unordered_set>
#include <cstdint>

class AnomalyDetector {
private:
    // Har IP ke packets count karne ke liye threshold map
    std::unordered_map<std::string, int> packetCountMap;
    const int THRESHOLD_LIMIT = 100; // Agar 100 se zyada packets hon toh alert generate ho

    // Har source IP ne kitne alag alag destination ports ko probe kiya
    std::unordered_map<std::string, std::unordered_set<uint16_t>> portsPerIp;
    const int PORT_SCAN_THRESHOLD = 20; // 20 se zyada alag ports = port scan

public:
    // Purana version: sirf packet count (ICMP / ports ke baghair)
    void analyzePacket(const std::string& srcIp) {
        packetCountMap[srcIp]++;
    }

    // Naya version: TCP/UDP packets ke liye destination port bhi record karta hai
    void analyzePacket(const std::string& srcIp, uint16_t dstPort) {
        packetCountMap[srcIp]++;
        portsPerIp[srcIp].insert(dstPort);
    }

    void evaluateTraffic() {
        std::cout << "\n--- Intrusion Detection System (IDS) Report ---" << std::endl;
        bool threatDetected = false;

        for (const auto& pair : packetCountMap) {
            if (pair.second > THRESHOLD_LIMIT) {
                std::cout << "[ALERT] Potential Port Scan / High-Volume Activity Detected from IP: "
                          << pair.first << " | Total Packets: " << pair.second << std::endl;
                threatDetected = true;
            }
        }

        for (const auto& pair : portsPerIp) {
            if (static_cast<int>(pair.second.size()) > PORT_SCAN_THRESHOLD) {
                std::cout << "[ALERT] Port Scan Detected from IP: " << pair.first
                          << " | Distinct Destination Ports: " << pair.second.size() << std::endl;
                threatDetected = true;
            }
        }

        if (!threatDetected) {
            std::cout << "[Safe] No anomalous traffic spikes detected under current threshold." << std::endl;
        }
    }
};