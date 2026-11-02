#pragma once
#include <string>
#include <iostream>
#include <fstream>
#include <cstdint>
#include "../stats/TopTalkerHeap.h"
#include "../detector/AnomalyDetector.h"

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

// ---- #23: TCP / UDP headers ----
struct TCPHeader {
    uint16_t src_port;
    uint16_t dest_port;
    uint32_t seq;
    uint32_t ack;
    uint8_t  data_offset;   // upper 4 bits = header length in 32-bit words
    uint8_t  flags;         // FIN=0x01 SYN=0x02 RST=0x04 PSH=0x08 ACK=0x10 URG=0x20
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent_ptr;
};

struct UDPHeader {
    uint16_t src_port;
    uint16_t dest_port;
    uint16_t length;
    uint16_t checksum;
};

// TCP flag bit masks
const uint8_t TCP_FIN = 0x01;
const uint8_t TCP_SYN = 0x02;
const uint8_t TCP_RST = 0x04;
const uint8_t TCP_PSH = 0x08;
const uint8_t TCP_ACK = 0x10;
const uint8_t TCP_URG = 0x20;

// IP protocol numbers
const uint8_t PROTO_ICMP = 1;
const uint8_t PROTO_TCP  = 6;
const uint8_t PROTO_UDP  = 17;

class PcapReader {
private:
    std::string filePath;

    // Temporary: prints the first few TCP/UDP packets so ports/flags can be checked
    // against Wireshark. Set to false (or remove) once parsing is verified.
    static const bool DEBUG_PORTS = false;
    static const int  DEBUG_LIMIT = 12;

public:
    explicit PcapReader(const std::string& path) : filePath(path) {}

    bool readPackets(TopTalkerHeap& tracker, AnomalyDetector& detector) {
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
        int tcpCount = 0, udpCount = 0, icmpCount = 0, otherCount = 0;
        int debugShown = 0;

        while (file.read(reinterpret_cast<char*>(&p_header), sizeof(p_header))) {
            std::string packetData(p_header.incl_len, '\0');
            file.read(&packetData[0], p_header.incl_len);

            // Need at least Ethernet + minimum IP header
            if (p_header.incl_len < sizeof(EthernetHeader) + sizeof(IPHeader)) {
                continue;
            }

            // Only IPv4 (0x0800). This skips ARP and other non-IP frames.
            const EthernetHeader* eth = reinterpret_cast<const EthernetHeader*>(packetData.data());
            if (ntohs(eth->ether_type) != 0x0800) {
                continue;
            }

            const IPHeader* ip_header = reinterpret_cast<const IPHeader*>(packetData.data() + sizeof(EthernetHeader));

            // IP header length is variable: IHL (lower 4 bits) * 4 bytes
            size_t ipLen = (ip_header->ver_ihl & 0x0F) * 4;
            if (ipLen < sizeof(IPHeader) || p_header.incl_len < sizeof(EthernetHeader) + ipLen) {
                continue;
            }

            in_addr src_addr;
            src_addr.s_addr = ip_header->src_ip;
            std::string srcIpStr = inet_ntoa(src_addr);

            in_addr dst_addr;
            dst_addr.s_addr = ip_header->dest_ip;
            std::string dstIpStr = inet_ntoa(dst_addr);

            // Transport layer starts right after the IP header
            const char* transport = packetData.data() + sizeof(EthernetHeader) + ipLen;
            size_t remaining = p_header.incl_len - sizeof(EthernetHeader) - ipLen;

            uint16_t srcPort = 0, dstPort = 0;
            uint8_t tcpFlags = 0;
            const char* protoName = "OTHER";

            if (ip_header->protocol == PROTO_TCP && remaining >= sizeof(TCPHeader)) {
                const TCPHeader* tcp = reinterpret_cast<const TCPHeader*>(transport);
                srcPort  = ntohs(tcp->src_port);
                dstPort  = ntohs(tcp->dest_port);
                tcpFlags = tcp->flags;
                protoName = "TCP";
                tcpCount++;
            } else if (ip_header->protocol == PROTO_UDP && remaining >= sizeof(UDPHeader)) {
                const UDPHeader* udp = reinterpret_cast<const UDPHeader*>(transport);
                srcPort = ntohs(udp->src_port);
                dstPort = ntohs(udp->dest_port);
                protoName = "UDP";
                udpCount++;
            } else if (ip_header->protocol == PROTO_ICMP) {
                protoName = "ICMP";
                icmpCount++;
            } else {
                otherCount++;
            }

            if (DEBUG_PORTS && debugShown < DEBUG_LIMIT && (ip_header->protocol == PROTO_TCP || ip_header->protocol == PROTO_UDP)) {
                std::cout << "[Debug] " << protoName << " " << srcIpStr << ":" << srcPort
                          << " -> " << dstIpStr << ":" << dstPort;
                if (ip_header->protocol == PROTO_TCP) {
                    std::cout << " flags=0x" << std::hex << static_cast<int>(tcpFlags) << std::dec;
                    if (tcpFlags & TCP_SYN) std::cout << " SYN";
                    if (tcpFlags & TCP_ACK) std::cout << " ACK";
                    if (tcpFlags & TCP_RST) std::cout << " RST";
                    if (tcpFlags & TCP_FIN) std::cout << " FIN";
                }
                std::cout << std::endl;
                debugShown++;
            }

            // Traffic ko TopTalkerHeap aur AnomalyDetector mein add karein
            tracker.addTraffic(srcIpStr, p_header.incl_len);
          if (dstPort != 0) detector.analyzePacket(srcIpStr, dstPort);
else detector.analyzePacket(srcIpStr);

            packetCount++;
        }

        std::cout << "[Info] Total Processed Packets: " << packetCount << std::endl;
        std::cout << "[Info] TCP: " << tcpCount << " | UDP: " << udpCount
                  << " | ICMP: " << icmpCount << " | Other: " << otherCount << std::endl;
        return true;
    }
};