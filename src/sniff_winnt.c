#include "sniff.h"
#include <stdio.h>
#include <windows.h>

const char* serial_open(SNIFF_RESOURCE *res, int speed) {
  DCB dcb;
  FillMemory(&dcb, sizeof(dcb), 0);
  int count = snprintf(res->path, MAXPATH + 1, "//./%s", res->device);
  if (count <= 0 || count > MAXPATH) {
    return "Path formatting failed";
  }
  res->handle = CreateFile(res->path, GENERIC_READ | GENERIC_WRITE, 0, 0,
                           OPEN_EXISTING, 0, 0);
  if (res->handle == INVALID_HANDLE_VALUE) {
    return "CreateFile failed";
  }
  if (!GetCommState(res->handle, &dcb)) {
    return "GetCommState failed";
  }

  dcb.DCBlength = sizeof(DCB);
  dcb.fBinary = TRUE;

  // BAUDRATE
  if (speed == 1200) {
    dcb.BaudRate = CBR_1200;
  } else if (speed == 2400) {
    dcb.BaudRate = CBR_2400;
  } else if (speed == 4800) {
    dcb.BaudRate = CBR_4800;
  } else if (speed == 9600) {
    dcb.BaudRate = CBR_9600;
  } else if (speed == 14400) {
    dcb.BaudRate = CBR_14400;
  } else if (speed == 19200) {
    dcb.BaudRate = CBR_19200;
  } else if (speed == 38400) {
    dcb.BaudRate = CBR_38400;
  } else if (speed == 57600) {
    dcb.BaudRate = CBR_57600;
  } else if (speed == 115200) {
    dcb.BaudRate = CBR_115200;
  } else if (speed == 128000) {
    dcb.BaudRate = CBR_128000;
  } else if (speed == 256000) {
    dcb.BaudRate = CBR_256000;
  } else {
    return "Invalid speed";
  }

  // config
  if (strcmp(res->config, "8N1") == 0) {
    dcb.ByteSize = 8;
    dcb.Parity = NOPARITY;
  } else if (strcmp(res->config, "7E1") == 0) {
    dcb.ByteSize = 7;
    dcb.Parity = EVENPARITY;
  } else if (strcmp(res->config, "7O1") == 0) {
    dcb.ByteSize = 7;
    dcb.Parity = ODDPARITY;
  } else {
    return "Invalid config";
  }

  // completely non-blocking read
  COMMTIMEOUTS ct;
  ct.ReadIntervalTimeout = MAXDWORD;
  ct.ReadTotalTimeoutConstant = 0;
  ct.ReadTotalTimeoutMultiplier = 0;
  ct.WriteTotalTimeoutConstant = 0;
  ct.WriteTotalTimeoutMultiplier = 0;

  if (!SetCommTimeouts(res->handle, &ct)) {
    return "SetCommTimeouts failed";
  }

  if (!SetCommState(res->handle, &dcb)) {
    return "SetCommState failed";
  }

  return NULL;
}

const char* serial_available(SNIFF_RESOURCE *res, COUNT *pcount) {
  COMSTAT baudStat;

  if (!ClearCommError(res->handle, NULL, &baudStat)) {
    return "ClearCommError failed";
  }

  *pcount = baudStat.cbInQue;

  return NULL;
}

const char* serial_read(SNIFF_RESOURCE *res, unsigned char *buffer, COUNT size, COUNT *pcount) {
  DWORD count = 0;

  if (!ReadFile(res->handle, buffer, size, &count, NULL)) {
    return "ReadFile failed";
  }

  *pcount = count;

  if (size != count) {
    return "ReadFile mismatch";
  }
  
  return NULL;
}

const char* serial_write(SNIFF_RESOURCE *res, unsigned char *buffer, COUNT size) {
  DWORD count = 0;

  if (!WriteFile(res->handle, buffer, size, &count, NULL)) {
    return "WriteFile failed";
  }

  if (size != count) {
    return "WriteFile mismatch";
  }

  return NULL;
}

const char* serial_block(SNIFF_RESOURCE *res) {
  return "Not implemented";
}

const char* serial_close(SNIFF_RESOURCE *res) {
  HANDLE handle = res->handle;
  res->handle = INVALID_HANDLE_VALUE;

  if (handle == INVALID_HANDLE_VALUE) {
    return "Handle already closed";
  }

  if (!CloseHandle(handle)) {
    return "CloseHandle failed";
  }

  return NULL;
}
