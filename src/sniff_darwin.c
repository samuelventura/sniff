#include "sniff.h"
#include <termios.h>
#include <fcntl.h>

void serial_open(SNIFF_RESOURCE *res, int speed) {
  serial_open_flags(res, speed, O_RDWR | O_NOCTTY | O_NONBLOCK);
}

int serial_baud(int speed) {
  switch (speed) {
    case 50: return B50;
    case 75: return B75;
    case 110: return B110;
    case 134: return B134;
    case 150: return B150;
    case 200: return B200;
    case 300: return B300;
    case 600: return B600;
    case 1200: return B1200;
    case 1800: return B1800;
    case 2400: return B2400;
    case 4800: return B4800;
    case 7200: return B7200;
    case 9600: return B9600;
    case 14400: return B14400;
    case 19200: return B19200;
    case 28800: return B28800;
    case 38400: return B38400;
    case 57600: return B57600;
    case 76800: return B76800;
    case 115200: return B115200;
    case 230400: return B230400;
    default: return -1;
  }
}
