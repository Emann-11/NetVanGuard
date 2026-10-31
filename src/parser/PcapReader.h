#pragma once
#include <string>
#include <iostream>
#include <fstream>
#include <cstdint>

// Windows aur Linux dono ke liye compatible network headers
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#endif

struct PcapGlobalHeader {
    uint32_t magic_number;
    uint16_t version_major;
    uint16_t version_minor;
    int32_t  thiszone;
    uint32_t sigfigs;
    uint32_t snaplen;
    uint32_t network;
};

struct PcapPacketHeader {
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint32_t incl_len;
    uint32_t orig_len;
};

struct EthernetHeader {
    uint8_t dest_mac[6];
    uint8_t src_mac[6];
    uint16_t ether_type;
};

struct IPHeader {
    uint8_t ver_ihl;
    uint8_t tos;
    uint16_t total_length;
    uint16_t identification;
    uint16_t flags_fragment;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    uint32_t src_ip;
    uint32_t dest_ip;
};

class PcapReader {
private:
    std::string filePath;
public:
    explicit PcapReader(const std::string& path) : filePath(path) {}
    
    bool readPackets() {
        std::ifstream file(filePath, std::ios::binary);
        if (!file.is_open()) {
            std::cout << "[Error] PCAP file open nahi ho saki: " << filePath << std::endl;
            return false;
        }

        PcapGlobalHeader g_header;
        file.read(reinterpret_cast<char*>(&g_header), sizeof(g_header));
        std::cout << "[Success] PCAP Global Header read! Magic Number: " << std::hex << g_header.magic_number << std::dec << std::endl;

        PcapPacketHeader p_header;
        int packetCount = 0;

        while (file.read(reinterpret_cast<char*>(&p_header), sizeof(p_header))) {
            std::string packetData(p_header.incl_len, '\0');
            file.read(&packetData[0], p_header.incl_len);

            if (p_header.incl_len < sizeof(EthernetHeader) + sizeof(IPHeader)) {
                continue;
            }

            const IPHeader* ip_header = reinterpret_cast<const IPHeader*>(packetData.data() + sizeof(EthernetHeader));

            in_addr src_addr, dest_addr;
            src_addr.s_addr = ip_header->src_ip;
            dest_addr.s_addr = ip_header->dest_ip;

            std::cout << "[Packet #" << ++packetCount << "] Source IP: " << inet_ntoa(src_addr) 
                      << " | Dest IP: " << inet_ntoa(dest_addr) 
                      << " | Length: " << p_header.incl_len << " bytes" << std::endl;
        }

        return true;
    }
};