#include "parser/PcapReader.h"
#include "stats/TopTalkerHeap.h"
#include "detector/AnomalyDetector.h"
#include <iostream>

class EngineController {
public:
    void runEngine() {
        std::cout << "[Engine] NetVanguard Full Pipeline with IDS Started..." << std::endl;
        
        PcapReader reader("../samples/nmap_standard_scan.pcap");
        TopTalkerHeap tracker;
        AnomalyDetector detector;

        reader.readPackets(tracker, detector);

        detector.evaluateTraffic();
        tracker.displayStats();
    }
};