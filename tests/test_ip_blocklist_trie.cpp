// Standalone test for src/detector/ip_blocklist_trie.h (issue #24).
// Build from the repo root:  g++ -g tests/test_ip_blocklist_trie.cpp -o trie_test.exe
// Run:                       .\trie_test.exe

#include "../src/detector/ip_blocklist_trie.h"
#include <iostream>

static int failures = 0;

static void check(bool condition, const std::string& label) {
    std::cout << (condition ? "[PASS] " : "[FAIL] ") << label << std::endl;
    if (!condition) ++failures;
}

int main() {
    using netvanguard::IPBlocklistTrie;

    IPBlocklistTrie empty;
    check(!empty.contains("192.168.100.103"), "empty trie blocks nothing");

    IPBlocklistTrie bl;
    check(bl.insert("10.0.0.5"), "insert exact IP");
    check(bl.insert("192.168.100.0/24"), "insert /24 range");
    check(bl.insert("172.16.0.0/12"), "insert /12 range");
    check(bl.size() == 3, "size is 3");

    // exact IP
    check(bl.contains("10.0.0.5"), "10.0.0.5 is blocked (exact)");
    check(!bl.contains("10.0.0.6"), "10.0.0.6 is not blocked");

    // /24 range
    check(bl.contains("192.168.100.103"), "192.168.100.103 is blocked (inside /24)");
    check(bl.contains("192.168.100.0"), "192.168.100.0 is blocked (range start)");
    check(bl.contains("192.168.100.255"), "192.168.100.255 is blocked (range end)");
    check(!bl.contains("192.168.101.1"), "192.168.101.1 is not blocked (outside /24)");

    // /12 range: 172.16.0.0 - 172.31.255.255
    check(bl.contains("172.31.255.255"), "172.31.255.255 is blocked (inside /12)");
    check(!bl.contains("172.32.0.1"), "172.32.0.1 is not blocked (outside /12)");

    // duplicate entry does not grow the trie count
    check(bl.insert("10.0.0.5"), "re-insert same entry is accepted");
    check(bl.size() == 3, "size still 3 after duplicate");

    // invalid input
    IPBlocklistTrie bad;
    check(!bad.insert("300.1.1.1"), "reject octet above 255");
    check(!bad.insert("1.2.3"), "reject 3 octets");
    check(!bad.insert("1.2.3.4.5"), "reject 5 octets");
    check(!bad.insert("1.2.3.4/33"), "reject prefix above 32");
    check(!bad.insert("1.2.3.4/"), "reject empty prefix");
    check(!bad.insert("abc"), "reject text");
    check(!bad.insert(""), "reject empty string");
    check(bad.size() == 0, "invalid entries are not stored");
    check(!bl.contains("not-an-ip"), "contains() on invalid text returns false");

    // /0 blocks everything, /32 equals exact
    IPBlocklistTrie all;
    all.insert("0.0.0.0/0");
    check(all.contains("8.8.8.8"), "0.0.0.0/0 blocks every IP");
    IPBlocklistTrie one;
    one.insert("1.2.3.4/32");
    check(one.contains("1.2.3.4") && !one.contains("1.2.3.5"), "/32 matches only that IP");

    std::cout << (failures == 0 ? "\nAll tests passed." : "\nSome tests FAILED.") << std::endl;
    return failures == 0 ? 0 : 1;
}
