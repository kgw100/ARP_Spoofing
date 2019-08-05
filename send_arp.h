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
#pragma pack (1) //Sort Structure

typedef struct ARP_PACKET_Struct{
    uint8_t D_Mac[6];
    uint8_t S_Mac[6];
    uint16_t Eth_type;
    uint16_t HW_Type;
    uint16_t PT_Type;
    uint8_t HAL;
    uint8_t PAL;
    uint16_t Oper_Code;
    uint8_t SHW_Adr[6];
    uint32_t SPT_Adr;
    uint8_t DHW_Adr[6];
    uint32_t DPT_Adr;
}ARP;


unsigned char * find_Attacker_Mac(const char *dev);
void usage();
