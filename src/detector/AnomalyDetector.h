#pragma once
#include <string>
#include <iostream>
#include <unordered_map>

class AnomalyDetector {
private:
    // Har IP ke packets count karne ke liye threshold map
    std::unordered_map<std::string, int> packetCountMap;
    const int THRESHOLD_LIMIT = 100; // Agar 100 se zyada packets hon toh alert generate ho

public:
    void analyzePacket(const std::string& srcIp) {
        packetCountMap[srcIp]++;
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

        if (!threatDetected) {
            std::cout << "[Safe] No anomalous traffic spikes detected under current threshold." << std::endl;
        }
    }
};