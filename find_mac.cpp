#include <sfdafx.h>
#include <send_arp.h>


unsigned char * find_Attacker_Mac(const char *dev)
{
    struct ifreq *ifr=(ifreq *)malloc(sizeof(ifreq));
    int s;
    memset(ifr, 0x00, sizeof(*ifr));
    strcpy(ifr->ifr_name, dev);

      if((s=socket(AF_UNIX,SOCK_DGRAM,0))<0)
      {
          perror("socket");
          exit(EXIT_FAILURE);
      }

     if (ioctl(s, SIOCGIFHWADDR, ifr) < 0) {
       perror("ioctl");
       exit(EXIT_FAILURE);
     }
    unsigned char * Attacker_mac = (unsigned char *)malloc(sizeof(char)*6);
    Attacker_mac = (unsigned char *)ifr->ifr_hwaddr.sa_data;
    close(s);
    free(ifr);
    return Attacker_mac;
}

const u_char* find_Sender_Mac(pcap* handle, pcap_pkthdr* header, ARP *Sen_ARP_Pac,const u_char* packet)
{
    while (true) { // if it receives packet, break;

          pcap_sendpacket(handle,(unsigned char *)Sen_ARP_Pac,sizeof(ARP)); //Send request
          int res = pcap_next_ex(handle, &header, &packet);

          if (res == 0) continue;
          if (res == -1 || res == -2)
            break;

         uint8_t OpCode= packet[21];
         uint16_t eth_type=uint16_t((packet[12]<<8)|packet[13]);
         uint32_t sender_ip = uint32_t((packet[28]<<24 )| (packet[29]<<16)| (packet[30] <<8)| packet[31]);
         uint8_t Dst_mac[6];
         for(int i=0; i<6;i++) Dst_mac[i]=packet[32+i];

         //compare Captured Packet and condition, Because it is reply. so Send_ip and dest_ip are reversed.

        if((ARP_Number==eth_type)&& (OC_Rep== OpCode)&& (Sen_ARP_Pac->ARP_Header.DPT_Adr ==ntohl(sender_ip))
                && (strcmp((const char *)Dst_mac,(const char *)Sen_ARP_Pac->ARP_Header.SHW_Adr)==0))
          {
            return packet;
          }
         else
            continue;
    }
    return nullptr;
}

const u_char * find_Target_Mac(pcap* handle, pcap_pkthdr* header, ARP *Tar_ARP_Pac,const u_char* packet)
{

    while (true) { // if it receives packet, break;
          pcap_sendpacket(handle,(unsigned char *)Tar_ARP_Pac,sizeof(ARP)); //Send request
          int res = pcap_next_ex(handle, &header, &packet);//read Packet

          if (res == 0) continue;
          if (res == -1 || res == -2)
            break;

         uint8_t OpCode= packet[21];
         uint16_t eth_type=uint16_t((packet[12]<<8)|packet[13]);
         uint32_t target_ip = uint32_t((packet[28]<<24 )| (packet[29]<<16)| (packet[30] <<8)| packet[31]);
         uint8_t Dst_mac[6];
         uint8_t Tar_mac[6];
         for(int i=0; i<6;i++) Dst_mac[i]=packet[32+i];
         for(int i=0; i<6;i++) Tar_mac[i]=packet[i+6];
         //compare Captured Packet and condition, Because it is reply. so Send_ip and dest_ip are reversed.
         printf("DST_mac:");
         for(int i=0; i<6; i++)printf("%02x",Dst_mac[i]);
         printf("\n");
         printf("Tar_mac:");
         for(int i=0; i<6; i++)printf("%02x",Tar_mac[i]);
          printf("\n");
         printf("SHW_Adr:");
          for(int i=0; i<6; i++)printf("%02x",Tar_ARP_Pac->ARP_Header.SHW_Adr[i]);
          printf("\n");

        if((ARP_Number==eth_type)&& (OC_Rep== OpCode)&& (Tar_ARP_Pac->ARP_Header.DPT_Adr ==ntohl(target_ip)
               && (strcmp((const char *)Dst_mac,(const char *)Tar_ARP_Pac->ARP_Header.SHW_Adr)==0)))
          {
              printf("Succes2!!\n");
              return packet;
          }
         else{
            continue;
        }
        }
}
