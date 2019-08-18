#pragma once
#pragma pack (1);
#include <termio.h>
#include <fcntl.h>

int linux_kbhit();
char linux_getch();
char getKey();
void usage();
