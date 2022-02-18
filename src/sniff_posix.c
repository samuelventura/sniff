#include "sniff.h"
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <termios.h>
#include <unistd.h>

void serial_open_flags(SNIFF_RESOURCE *res, int speed, int flags) {
  struct termios fdt;
  memset(&fdt, 0, sizeof(fdt));
  res->fd = -1;
  int count = snprintf(res->path, MAXPATH + 1, "%s", res->device);
  if (count <= 0 || count > MAXPATH) {
    res->error = "Path formatting failed";
    return;
  }
  res->fd = open(res->path, flags);
  if (res->fd < 0) {
    res->error = "open failed";
    return;
  }
  if (isatty(res->fd) < 0) {
    res->error = "isatty failed";
    return;
  }
  if (tcgetattr(res->fd, &fdt) < 0) {
    res->error = "tcgetattr failed";
    return;
  }

  fdt.c_cflag |= CLOCAL | CREAD;
  fdt.c_lflag &= ~(ECHO | ECHONL | ICANON | ISIG | IEXTEN);
  fdt.c_iflag &= ~(INLCR | IGNCR | ICRNL | IXON | IXOFF | IXANY);
  fdt.c_oflag &= ~(ONLCR | OCRNL | OPOST);
 
  int baud = serial_baud(speed);
  if (baud > 0) {
    cfsetispeed(&fdt, baud);
    cfsetospeed(&fdt, baud);
  } else {
    res->error = "Invalid speed";
    return;
  }

  // config
  if (strcmp(res->config, "8N1") == 0) {
    fdt.c_cflag |= CS8;
    fdt.c_cflag &= ~PARENB;
    fdt.c_cflag &= ~CSTOPB;
    fdt.c_cflag &= ~CSIZE;
    fdt.c_cflag |= CS8;
  } else if (strcmp(res->config, "7E1") == 0) {
    fdt.c_cflag |= PARENB;
    fdt.c_cflag &= ~PARODD;
    fdt.c_cflag &= ~CSTOPB;
    fdt.c_cflag &= ~CSIZE;
    fdt.c_cflag |= CS7;
    fdt.c_iflag |= INPCK;
    fdt.c_iflag |= ISTRIP;
  } else if (strcmp(res->config, "7O1") == 0) {
    fdt.c_cflag |= PARENB;
    fdt.c_cflag |= PARODD;
    fdt.c_cflag &= ~CSTOPB;
    fdt.c_cflag &= ~CSIZE;
    fdt.c_cflag |= CS7;
    fdt.c_iflag |= INPCK;
    fdt.c_iflag |= ISTRIP;
  } else {
    res->error = "Invalid config";
    return;
  }

  // non-blocking
  fdt.c_cc[VTIME] = 0;
  fdt.c_cc[VMIN] = 0;

  if (tcsetattr(res->fd, TCSANOW, &fdt) < 0) {
    res->error = "tcsetattr failed";
    return;
  }
}

void serial_available(SNIFF_RESOURCE *res) {
  size_t count = 0;
  if (ioctl(res->fd, FIONREAD, &count) < 0) {
    res->error = "ioctl failed";
    return;
  }
  res->count = count;
}

void serial_read(SNIFF_RESOURCE *res, unsigned char *buffer, COUNT size) {
  int count = read(res->fd, buffer, size);
  if (count < 0) {
    res->error = "read failed";
    return;
  }
  if (size != count) {
    res->error = "read mismatch";
    return;
  }
  res->count = count;
}

void serial_write(SNIFF_RESOURCE *res, unsigned char *buffer, COUNT size) {
  int count = write(res->fd, buffer, size);
  if (count < 0) {
    res->error = "write failed";
    return;
  }
  if (size != count) {
    res->error = "write mismatch";
    return;
  }
  res->count = count;
}

void serial_close(SNIFF_RESOURCE *res) {
  int fd = res->fd;
  res->fd = -1;
  if (fd < 0) {
    res->error = "fd already closed";
    return;
  }
  if (close(fd) < 0) {
    res->error = "close failed";
    return;
  }
}
