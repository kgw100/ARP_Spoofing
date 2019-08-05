#include <send_arp.h>

unsigned char * find_Attacker_Mac(const char *dev)
{
    struct ifreq ifr;
    int s;
    memset(&ifr, 0x00, sizeof(ifr));
      strcpy(ifr.ifr_name, dev);

     if ((s = socket(AF_INET, SOCK_STREAM,0)) < 0) {
       perror("socket");
      // exit(EXIT_SUCCESS);
     }

     if (ioctl(s, SIOCGIFHWADDR, &ifr) < 0) {
       perror("ioctl");
      // exit(EXIT_SUCCESS);
     }
    unsigned char * Attacker_mac = (unsigned char *)malloc(sizeof(char)*6);
    Attacker_mac = (unsigned char *)ifr.ifr_hwaddr.sa_data;

    close(s);
    return Attacker_mac;
}

void usage() {
  printf("syntax: send_arp <interface> <Sender> <Target> \n");
  printf("sample: send_arp wlan0 192.168.10.223 192.168.10.1\n");
}
