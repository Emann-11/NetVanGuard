#include "parser/PcapReader.h"
#include "stats/TopTalkerHeap.h"
#include <iostream>

class EngineController {
public:
    void runEngine() {
        std::cout << "[Engine] NetVanguard Packet Extraction Started..." << std::endl;
        
        // Read actual packets from sample pcap
        PcapReader reader("../samples/nmap_standard_scan.pcap");
        reader.readPackets();
    }
};