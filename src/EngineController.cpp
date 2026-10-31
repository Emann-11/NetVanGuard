#include "parser/PcapReader.h"
#include "stats/TopTalkerHeap.h"
#include <iostream>

class EngineController {
public:
    void runEngine() {
        std::cout << "[Engine] NetVanguard Analysis Started..." << std::endl;
        
        // Test Pcap Reader with sample file
       PcapReader reader("../samples/nmap_standard_scan.pcap");
        reader.readPacketHeader();
        
        // Test DSA Statistics
        TopTalkerHeap tracker;
        tracker.addTraffic("192.168.1.10", 1500);
        tracker.addTraffic("10.0.0.5", 3200);
        tracker.displayStats();
    }
};