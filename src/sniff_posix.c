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
#include <pthread.h>

const char* serial_valid_speed(int speed) {
  int baud = serial_baud(speed);
  if (baud > 0) {
    return NULL;
  } else {
    return "Invalid speed";
  }
}

const char* serial_open_flags(SNIFF_RESOURCE *res, int speed, int flags) {
  struct termios fdt;
  memset(&fdt, 0, sizeof(fdt));
  int count = snprintf(res->path, MAXPATH + 1, "%s", res->device);
  if (count <= 0 || count > MAXPATH) {
    return "Path formatting failed";
  }
  res->fd = open(res->path, flags);
  if (res->fd < 0) {
    return "open failed";
  }
  if (isatty(res->fd) < 0) {
    return "isatty failed";
  }
  if (tcgetattr(res->fd, &fdt) < 0) {
    return "tcgetattr failed";
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
    return "Invalid speed";
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
    return "Invalid config";
  }

  // non-blocking
  fdt.c_cc[VTIME] = 0;
  fdt.c_cc[VMIN] = 0;

  if (tcsetattr(res->fd, TCSANOW, &fdt) < 0) {
    return "tcsetattr failed";
  }
  return NULL;
}

const char* serial_available(SNIFF_RESOURCE *res, COUNT *pcount) {
  int count = 0;
  if (ioctl(res->fd, FIONREAD, &count) < 0) {
    return "ioctl failed";
  }
  *pcount = count;
  return NULL;
}

const char* serial_read(SNIFF_RESOURCE *res, unsigned char *buffer, COUNT size, COUNT *pcount) {
  int count = read(res->fd, buffer, size);
  if (count < 0) {
    return "read failed";
  }
  *pcount = count;
  if (size != count) {
    return "read mismatch";
  }
  return NULL;
}

const char* serial_write(SNIFF_RESOURCE *res, unsigned char *buffer, COUNT size) {
  int count = write(res->fd, buffer, size);
  if (count < 0) {
    return "write failed";
  }
  if (size != count) {
    return "write mismatch";
  }
  return NULL;
}

const char* serial_close(SNIFF_RESOURCE *res) {
  if (res->closed > 0) {
    return "already closed";
  }
  if (close(res->fd) < 0) {
    return "close failed";
  }
  return NULL;
}

const char* serial_listen_start(SNIFF_RESOURCE *res) {
  const char* error;
  if ((error = serial_block(res)) != NULL) {
    return error;
  }
  if (pipe(res->pipes)==-1) {
    return "pipe failed";
  }
  if (pthread_create(&res->thread, NULL, serial_thread, (void*)res)!=0) {
    return "pthread_create failed";
  }
  return NULL;
}

const char* serial_listen_stop(SNIFF_RESOURCE *res) {
  write(res->pipes[1], "*", 1);
  close(res->pipes[1]);
  pthread_cancel(res->thread);
  pthread_join(res->thread, NULL);
  close(res->pipes[0]);
  return NULL;
}

void* serial_thread(void *obj) {
  SNIFF_RESOURCE *res = obj;
  struct pollfd fds[2];
  fds[0].fd = res->fd;
  fds[1].fd = res->pipes[1];
  fds[0].events = POLLIN;
  fds[1].events = POLLIN | POLLHUP;

  while (1) {
    poll(fds, 2, -1);
    if (fds[0].revents & POLLIN) {
      COUNT size = 0;
      COUNT count = 0;
      serial_available(res, &size);
      unsigned char data[size];
      serial_read(res, data, size, &count);
      res->send(res, data, count);
    }
    if (fds[1].revents & POLLHUP) { break; }
  }
  
  return NULL;
}
