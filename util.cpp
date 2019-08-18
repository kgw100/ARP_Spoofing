#include <sfdafx.h>
#include <util.h>

char getKey()
{
    if(linux_kbhit())
    {
        return linux_getch();
    }
    return '\0';
}
int linux_kbhit()
{
    struct termios oldt, newt;
    int ch;
    int oldf;

    tcgetattr(STDIN_FILENO,&oldt);
    newt = oldt;
    newt.c_lflag&= ~(ICANON|ECHO);
    tcsetattr(STDIN_FILENO,TCSANOW,&newt);
    oldf = fcntl(STDIN_FILENO, F_GETFL, 0);
    fcntl(STDIN_FILENO,F_SETFL, oldf | O_NONBLOCK);
    ch = getchar();
    tcsetattr(STDIN_FILENO, TCSANOW,&oldt);
    fcntl(STDIN_FILENO,F_SETFL,oldf);
    if(ch != EOF)
    {
        ungetc(ch,stdin);
        return 1;
    }
    return 0;

}
char linux_getch()
{
    int ch;
    struct termios oldt, newt;
    tcgetattr(0,&oldt);
    newt = oldt;
    newt.c_lflag&= ~(ICANON|ECHO);
    newt.c_cc[VMIN] = 1;
    newt.c_cc[VTIME] = 0;
    tcsetattr(0, TCSAFLUSH, &newt);
    ch = getchar();
    tcsetattr(0,TCSAFLUSH, &oldt);
    return ch;

}

void usage() {
  printf("syntax: send_arp <interface> <Sender1> <Target1> <Sender2> <Target2>\n");
  printf("sample: send_arp wlan0 192.168.10.223 192.168.10.1 192.168.10.1 192.168.10.X\n");
}
void cmp_key(char key)
{

}
