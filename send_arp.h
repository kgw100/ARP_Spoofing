#pragma once
#include <pcap.h>
#include <netdb.h>
#include <sys/fcntl.h>
#include <sys/errno.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/ether.h>


#pragma pack (1) //Sorting Structure
#define IP_Number 0x0800
#define ARP_Number 0x0806
#define OC_Req 0x0001
#define OC_Rep 0x0002

typedef struct ETH_Struct{
    uint8_t D_Mac[6];
    uint8_t S_Mac[6];
    uint16_t Eth_type;
}Eth_Header;

typedef struct IP_Struct{
    uint8_t ip_header_len:4;
    uint8_t ip_version:4;
    uint8_t ip_tos;
    uint16_t ip_total_legth;
    uint16_t ip_id;
    uint16_t ip_frag_offset;
    uint8_t ip_ttl;
    uint8_t ip_protocol;
    uint32_t S_IP;
    uint32_t D_IP;
}IP_Header;

typedef struct TCP_Struct{
    const u_char *Tcp_Data;
}TCP_Header;

typedef struct ARP_Struct{
    uint16_t HW_Type;
    uint16_t PT_Type;
    uint8_t HAL;
    uint8_t PAL;
    uint16_t Oper_Code;
    uint8_t SHW_Adr[6];
    uint32_t SPT_Adr;
    uint8_t DHW_Adr[6];
    uint32_t DPT_Adr;
}ARP_Header;

typedef struct IP_PACKET_Struct{
    struct ETH_Struct Eth_Header;
    struct IP_Struct IP_Header;
    struct TCP_Struct TCP_Header;
}IP;


typedef struct ARP_PACKET_Struct{
    struct ETH_Struct Eth_Header;
    struct ARP_Struct ARP_Header;
}ARP;


unsigned char * find_Attacker_Mac(const char *dev);
const u_char* find_Sender_Mac(pcap* handle, pcap_pkthdr* header, ARP *ARP_Pac,const u_char* packet);
const u_char* find_Target_Mac(pcap* handle, pcap_pkthdr* header, ARP *Tar_ARP_Pac,const u_char* packet);

void ARP_REQ_ToSender_Set(const char *dev, ARP *ARP_Pac,uint32_t SenderIP);
void ARP_REP_ToSender_Set(ARP *ARP_pac,const char * argv[] ,const u_char* packet);
void Send_ARP_ToSender(pcap_t* handle, ARP *ARP_Pac, int packet_size);

void ARP_REQ_ToTarget_Set(const char *dev, ARP *Tar_ARP_Pac,uint32_t SenderIP ,uint32_t TargetIP);
void ARP_REP_ToTarget_Set(ARP * Tar_ARP_Pac,const char * argv[] ,const u_char* packet);
void Send_ARP_ToTarget(pcap_t* handle, ARP  *Tar_ARP_Pac, int packet_size);

void IP_REL_Set(pcap* handle, IP *IP_Pac, const u_char* target_packet
                ,const char * dev,const char *argv[]);
void Send_IP_REL(pcap_t* handle, pcap_pkthdr* header,ARP *Tar_ARP_Pac, ARP *Sen_ARP_Pac,const u_char* target_packet,const char * dev,const char *argv[]);



