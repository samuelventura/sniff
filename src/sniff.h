
#ifndef _SNIFF_H_
#define _SNIFF_H_

#include "erl_nif.h"

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

#ifdef _WIN32
#define OPEN_ERROR INVALID_HANDLE_VALUE
#else
#define OPEN_ERROR -1
#endif

typedef struct SNIFF_RESOURCE {
  #ifdef _WIN32
  HANDLE handle;
  #else
  int fd;
  #endif
  int open;
  int closed;
  int listen;
  ErlNifPid self;
  pthread_t thread;
  char path[MAXPATH + 1];
  char device[MAXPATH + 1];
  char config[3 + 1]; // 8N1 | 7E1 | 7O1
} SNIFF_RESOURCE;

const char* serial_open(SNIFF_RESOURCE *res, int speed);
const char* serial_open_flags(SNIFF_RESOURCE *res, int speed, int flags);
const char* serial_close(SNIFF_RESOURCE *res);
const char* serial_release(SNIFF_RESOURCE *res);
const char* serial_available(SNIFF_RESOURCE *res, COUNT *pcount);
const char* serial_read(SNIFF_RESOURCE *res, unsigned char *buffer, COUNT size, COUNT *pcount);
const char* serial_write(SNIFF_RESOURCE *res, unsigned char *buffer, COUNT size);
const char* serial_block(SNIFF_RESOURCE *res);
const char* serial_thread(SNIFF_RESOURCE *res, void *(*handler)(void *));
const char* serial_exit(SNIFF_RESOURCE *res);

#endif
