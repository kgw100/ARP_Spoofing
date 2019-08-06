#include <send_arp.h>

int main (int argc, const char * argv[])
{
   if (argc != 4) {
     usage();
     return -1;
   }

    struct pcap_pkthdr* header;
          const u_char* packet;
    const char *dev = argv[1];
    uint32_t SenderIP = inet_addr(argv[2]);
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    ARP *ARP_Pac = (ARP*)malloc(sizeof(ARP));

   if (handle == NULL) {
     fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
     return -1;
   }

    ARP_REQ_Set(dev,ARP_Pac, SenderIP);//Set ARP_Packet

    packet=find_Sender_Mac(handle,header,ARP_Pac,packet);

    ARP_REP_Set(ARP_Pac,argv,packet);

    Send_ARP(handle,ARP_Pac,sizeof(ARP));
   // free(ARP_Pac);
   //  return 0;
}
