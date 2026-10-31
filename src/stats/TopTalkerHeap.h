#pragma once
#include <string>
#include <iostream>
#include <unordered_map>

class TopTalkerHeap {
private:
    std::unordered_map<std::string, int> ipTrafficMap;
public:
    void addTraffic(const std::string& ip, int bytes) {
        ipTrafficMap[ip] += bytes;
    }
    
    void displayStats() {
        std::cout << "\n--- Network Traffic Statistics (Hash Map & Heap) ---" << std::endl;
        for (const auto& pair : ipTrafficMap) {
            std::cout << "IP Address: " << pair.first << " | Total Bytes: " << pair.second << std::endl;
        }
    }
};