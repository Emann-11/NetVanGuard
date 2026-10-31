#pragma once
#include <string>
#include <iostream>
#include <fstream>
#include <cstdint>

struct PcapGlobalHeader {
    uint32_t magic_number;
    uint16_t version_major;
    uint16_t version_minor;
    int32_t  thiszone;
    uint32_t sigfigs;
    uint32_t snaplen;
    uint32_t network;
};

class PcapReader {
private:
    std::string filePath;
public:
    explicit PcapReader(const std::string& path) : filePath(path) {}
    
    bool readPacketHeader() {
        std::ifstream file(filePath, std::ios::binary);
        if (!file.is_open()) {
            std::cout << "[Error] PCAP file open nahi ho saki: " << filePath << std::endl;
            return false;
        }
        PcapGlobalHeader header;
        file.read(reinterpret_cast<char*>(&header), sizeof(header));
        std::cout << "[Success] PCAP file successfully read! Magic Number: " << std::hex << header.magic_number << std::endl;
        return true;
    }
};