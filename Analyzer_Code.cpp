#include <iostream>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <unordered_map>
#include <chrono>

// Structure to track SYN packets for anomaly detection
struct FlowStats {
    uint32_t syn_count = 0;
    std::chrono::steady_clock::time_point last_seen;
};

// Global variables for simple anomaly detection
std::unordered_map<std::string, FlowStats> syn_tracker;
const uint32_t SYN_FLOOD_THRESHOLD = 20; // Max SYNs per second from a single IP
const uint32_t MAX_UDP_PAYLOAD_SIZE = 1400; // Anomaly threshold for oversized UDP

// Callback function triggered by libpcap for every captured packet
void packet_handler(u_char* user, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    std::cout << "\n[+] Captured Packet: Length = " << pkthdr->len << " bytes" << std::endl;

    // 1. Parse Ethernet Header
    struct ether_header* eth_header = (struct ether_header*) packet;
    if (ntohs(eth_header->ether_type) != ETHERTYPE_IP) {
        // Skip non-IPv4 traffic for simplicity
        return;
    }

    // 2. Parse IP Header (Offset by Ethernet header size)
    struct ip* ip_header = (struct ip*)(packet + sizeof(struct ether_header));
    std::string src_ip = inet_ntoa(ip_header->ip_src);
    // Duplicate string because inet_ntoa uses a static buffer
    std::string dst_ip = inet_ntoa(ip_header->ip_dst); 

    std::cout << "    Source IP: " << src_ip << " -> Dest IP: " << dst_ip << std::endl;

    // Calculate IP header length (handles variable options sizes)
    int ip_header_len = ip_header->ip_hl * 4;

    // 3. Protocol Filtering & Parsing
    if (ip_header->ip_p == IPPROTO_TCP) {
        // Parse TCP Header
        struct tcphdr* tcp_header = (struct tcphdr*)(packet + sizeof(struct ether_header) + ip_header_len);
        uint16_t src_port = ntohs(tcp_header->th_sport);
        uint16_t dst_port = ntohs(tcp_header->th_dport);

        std::cout << "    Protocol: TCP | Src Port: " << src_port << " | Dst Port: " << dst_port << std::endl;

        // --- ANOMALY DETECTION: TCP SYN Flood ---
        if (tcp_header->th_flags & TH_SYN) {
            auto now = std::chrono::steady_clock::now();
            auto& stats = syn_tracker[src_ip];

            // Reset window if more than 1 second has passed
            if (std::chrono::duration_cast<std::chrono::seconds>(now - stats.last_seen).count() >= 1) {
                stats.syn_count = 0;
            }

            stats.syn_count++;
            stats.last_seen = now;

            if (stats.syn_count > SYN_FLOOD_THRESHOLD) {
                std::cerr << "    [!] ALERT: Potential TCP SYN Flood detected from " << src_ip 
                          << " (" << stats.syn_count << " SYNs/sec)" << std::endl;
            }
        }

    } else if (ip_header->ip_p == IPPROTO_UDP) {
        // Parse UDP Header
        struct udphdr* udp_header = (struct udphdr*)(packet + sizeof(struct ether_header) + ip_header_len);
        uint16_t src_port = ntohs(udp_header->uh_sport);
        uint16_t dst_port = ntohs(udp_header->uh_dport);
        uint16_t udp_len = ntohs(udp_header->uh_ulen);

        std::cout << "    Protocol: UDP | Src Port: " << src_port << " | Dst Port: " << dst_port 
                  << " | Length: " << udp_len << std::endl;

        // --- ANOMALY DETECTION: Oversized UDP Payload ---
        if (udp_len > MAX_UDP_PAYLOAD_SIZE) {
            std::cerr << "    [!] ALERT: Oversized UDP Packet detected from " << src_ip 
                      << " Size: " << udp_len << " bytes (Possible amplification/exfiltration vector)" << std::endl;
        }
    } else {
        std::cout << "    Protocol: Other (0x" << std::hex << (int)ip_header->ip_p << std::dec << ")" << std::endl;
    }
}

int main(int argc, char* argv[]) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t* alldevs;
    pcap_if_t* device;

    // 1. Find available network devices
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        std::cerr << "Error finding devices: " << errbuf << std::endl;
        return 1;
    }

    // Use the first available interface
    device = alldevs;
    if (device == nullptr) {
        std::cerr << "No devices found. Ensure you are running as root/sudo." << std::endl;
        return 1;
    }

    std::cout << "[*] Sniffing on device: " << device->name << std::endl;

    // 2. Open the device for live capturing
    // Arguments: device name, snaplen (max bytes per packet), promisc mode, to_ms (timeout), errbuf
    pcap_t* handle = pcap_open_live(device->name, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        std::cerr << "Could not open device " << device->name << ": " << errbuf << std::endl;
        pcap_freealldevs(alldevs);
        return 1;
    }

    // Free the device list as we have opened our handle
    pcap_freealldevs(alldevs);

    // 3. Compile and apply a BPF (Berkeley Packet Filter) to capture only TCP and UDP
    struct bpf_program fp;
    char filter_exp[] = "tcp or udp";
    bpf_u_int32 net = 0; // Assuming default network layout for filter compilation

    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        std::cerr << "Bad filter expression: " << pcap_geterr(handle) << std::endl;
        return 1;
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        std::cerr << "Error setting filter: " << pcap_geterr(handle) << std::endl;
        return 1;
    }

    std::cout << "[*] Filter applied: '" << filter_exp << "'. Starting loop..." << std::endl;

    // 4. Enter processing loop (-1 means loop indefinitely until interrupted)
    pcap_loop(handle, -1, packet_handler, nullptr);

    // Close the handle (unreachable in infinite loop unless broken out manually)
    pcap_close(handle);
    return 0;
}
