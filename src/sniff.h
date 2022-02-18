
#ifndef _SNIFF_H_
#define _SNIFF_H_

#define UNUSED(x) (void)(x)
#define MIN(a,b) (((a)<(b))?(a):(b))
#define MAXPATH 255

#ifdef _WIN32
#include <windows.h>
#define COUNT DWORD
#define PADSIZE 4 // //./
#else
#include <termios.h>
#define COUNT int
#define PADSIZE 0 // absolutes only
int serial_baud(int speed);
#endif

typedef struct SNIFF_RESOURCE {
  #ifdef _WIN32
  HANDLE handle;
  #else
  int fd;
  #endif
  COUNT count;
  const char* error;
  char path[MAXPATH + 1];
  char device[MAXPATH + 1];
  char config[3 + 1]; // 8N1 | 7E1 | 7O1
} SNIFF_RESOURCE;

void serial_open(SNIFF_RESOURCE *res, int speed);
void serial_open_flags(SNIFF_RESOURCE *res, int speed, int flags);
void serial_close(SNIFF_RESOURCE *res);
void serial_release(SNIFF_RESOURCE *res);
void serial_available(SNIFF_RESOURCE *res);
void serial_read(SNIFF_RESOURCE *res, unsigned char *buffer, COUNT size);
void serial_write(SNIFF_RESOURCE *res, unsigned char *buffer, COUNT size);

#endif
