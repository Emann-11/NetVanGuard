#include "parser/PcapReader.h"
#include "stats/TopTalkerHeap.h"
#include <iostream>

class EngineController {
public:
    void runEngine() {
        std::cout << "[Engine] NetVanguard Full Pipeline Started..." << std::endl;
        
        PcapReader reader("../samples/nmap_standard_scan.pcap");
        TopTalkerHeap tracker;

        // Parse packets and feed data into traffic statistics tracker
        reader.readPackets(tracker);

        // Display final aggregated traffic statistics
        tracker.displayStats();
    }
};