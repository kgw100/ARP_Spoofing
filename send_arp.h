#pragma once
#include <stdint.h>
#include <stdio.h>
#include<pcap.h>
#include <netdb.h>
#include <unistd.h>
#include <string.h>
#include <sys/fcntl.h>
#include <sys/errno.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdlib.h>
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


typedef struct ARP_PACKET_Struct{
    struct ETH_Struct Eth_Header;
    struct ARP_Struct ARP_Header;
}ARP;


unsigned char * find_Attacker_Mac(const char *dev);
const u_char* find_Sender_Mac(pcap* handle,  struct pcap_pkthdr* header, ARP *ARP_Pac,const u_char* packet);
void usage();
void ARP_REQ_Set(const char *dev, ARP *ARP_Pac,uint32_t SenderIP);
void ARP_REP_Set(ARP *ARP_pac,const char * argv[] ,const u_char* packet);
void Send_ARP(pcap_t* handle, ARP *ARP_Pac, int packet_size);


