#pragma once
// IPv4 blocklist stored in a binary prefix trie (issue #24).
//
// Each node has two children: bit 0 and bit 1. An IPv4 address is 32 bits, so a lookup
// walks at most 32 nodes no matter how many entries are stored. An entry can be an exact
// IP ("10.0.0.5", same as /32) or a CIDR range ("192.168.100.0/24"). A range is stored
// by inserting only its first <prefix length> bits and marking that node as blocked, so
// any IP below that node is blocked.
//
// The string API takes dotted IPv4 text, so it works directly with the srcIpStr that
// PcapReader already produces. It does not need winsock.

#include <cstdint>
#include <string>
#include <vector>

namespace netvanguard {

class IPBlocklistTrie {
public:
    IPBlocklistTrie() { nodes_.emplace_back(); }  // node 0 is the root

    // Adds "a.b.c.d" or "a.b.c.d/len" (len 0-32). Returns false if the text is invalid.
    bool insert(const std::string& entry) {
        std::uint32_t ip = 0;
        int prefixLen = 32;
        if (!parseEntry(entry, ip, prefixLen)) return false;

        int cur = 0;
        for (int i = 0; i < prefixLen; ++i) {
            int bit = (ip >> (31 - i)) & 1;
            if (nodes_[cur].child[bit] == -1) {
                nodes_[cur].child[bit] = static_cast<int>(nodes_.size());
                nodes_.emplace_back();
            }
            cur = nodes_[cur].child[bit];
        }
        if (!nodes_[cur].blocked) {
            nodes_[cur].blocked = true;
            ++entries_;
        }
        return true;
    }

    // True if the IP is covered by any stored entry (exact match or inside a range).
    // Invalid IP text returns false.
    bool contains(const std::string& ip) const {
        std::uint32_t value = 0;
        if (!parseIPv4(ip, value)) return false;
        return contains(value);
    }

    // Same check for an IP already converted to a 32-bit number (a.b.c.d -> a<<24 | ...).
    bool contains(std::uint32_t ip) const {
        int cur = 0;
        if (nodes_[cur].blocked) return true;  // a /0 entry blocks everything
        for (int i = 0; i < 32; ++i) {
            int bit = (ip >> (31 - i)) & 1;
            int next = nodes_[cur].child[bit];
            if (next == -1) return false;
            cur = next;
            if (nodes_[cur].blocked) return true;
        }
        return false;
    }

    // Number of distinct entries stored.
    std::size_t size() const { return entries_; }

private:
    struct Node {
        int child[2] = {-1, -1};
        bool blocked = false;
    };

    std::vector<Node> nodes_;
    std::size_t entries_ = 0;

    // "a.b.c.d" -> 32-bit number. Exactly four octets, each 0-255, digits only.
    static bool parseIPv4(const std::string& text, std::uint32_t& out) {
        std::uint32_t result = 0;
        int octets = 0;
        std::size_t i = 0;
        while (i <= text.size()) {
            int digits = 0;
            int value = 0;
            while (i < text.size() && text[i] >= '0' && text[i] <= '9') {
                value = value * 10 + (text[i] - '0');
                ++digits;
                ++i;
                if (digits > 3 || value > 255) return false;
            }
            if (digits == 0) return false;
            result = (result << 8) | static_cast<std::uint32_t>(value);
            ++octets;
            if (i == text.size()) break;
            if (text[i] != '.') return false;
            ++i;
        }
        if (octets != 4) return false;
        out = result;
        return true;
    }

    // "a.b.c.d" or "a.b.c.d/len".
    static bool parseEntry(const std::string& entry, std::uint32_t& ip, int& prefixLen) {
        std::size_t slash = entry.find('/');
        if (slash == std::string::npos) {
            prefixLen = 32;
            return parseIPv4(entry, ip);
        }
        if (!parseIPv4(entry.substr(0, slash), ip)) return false;

        std::string lenText = entry.substr(slash + 1);
        if (lenText.empty() || lenText.size() > 2) return false;
        int len = 0;
        for (char c : lenText) {
            if (c < '0' || c > '9') return false;
            len = len * 10 + (c - '0');
        }
        if (len > 32) return false;
        prefixLen = len;
        return true;
    }
};

}  // namespace netvanguard
