#include "sniff.h"
#include <stdio.h>
#include <windows.h>

void serial_open(SNIFF_RESOURCE *res, int speed) {
  DCB dcb;
  FillMemory(&dcb, sizeof(dcb), 0);
  res->handle = INVALID_HANDLE_VALUE;
  int count = snprintf(res->path, MAXPATH + 1, "//./%s", res->device);
  if (count <= 0 || count > MAXPATH) {
    res->error = "Path formatting failed";
    return;
  }
  res->handle = CreateFile(res->path, GENERIC_READ | GENERIC_WRITE, 0, 0,
                           OPEN_EXISTING, 0, 0);
  if (res->handle == INVALID_HANDLE_VALUE) {
    res->error = "CreateFile failed";
    return;
  }
  if (!GetCommState(res->handle, &dcb)) {
    res->error = "GetCommState failed";
    return;
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
    res->error = "Invalid speed";
    return;
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
    res->error = "Invalid config";
    return;
  }

  // completely non-blocking read
  COMMTIMEOUTS ct;
  ct.ReadIntervalTimeout = MAXDWORD;
  ct.ReadTotalTimeoutConstant = 0;
  ct.ReadTotalTimeoutMultiplier = 0;
  ct.WriteTotalTimeoutConstant = 0;
  ct.WriteTotalTimeoutMultiplier = 0;

  if (!SetCommTimeouts(res->handle, &ct)) {
    res->error = "SetCommTimeouts failed";
    return;
  }

  if (!SetCommState(res->handle, &dcb)) {
    res->error = "SetCommState failed";
    return;
  }
}

void serial_available(SNIFF_RESOURCE *res) {
  COMSTAT baudStat;

  if (!ClearCommError(res->handle, NULL, &baudStat)) {
    res->error = "ClearCommError failed";
    return;
  }

  res->count = baudStat.cbInQue;
}

void serial_read(SNIFF_RESOURCE *res, unsigned char *buffer, COUNT size) {
  DWORD count = 0;

  if (!ReadFile(res->handle, buffer, size, &count, NULL)) {
    res->error = "ReadFile failed";
    return;
  }

  if (size != count) {
    res->error = "ReadFile mismatch";
    return;
  }

  res->count = count;
}

void serial_write(SNIFF_RESOURCE *res, unsigned char *buffer, COUNT size) {
  DWORD count = 0;

  if (!WriteFile(res->handle, buffer, size, &count, NULL)) {
    res->error = "WriteFile failed";
    return;
  }

  if (size != count) {
    res->error = "WriteFile mismatch";
    return;
  }

  res->count = count;
}

void serial_close(SNIFF_RESOURCE *res) {
  HANDLE handle = res->handle;
  res->handle = INVALID_HANDLE_VALUE;

  if (handle == INVALID_HANDLE_VALUE) {
    res->error = "Handle already closed";
    return;
  }

  if (!CloseHandle(handle)) {
    res->error = "CloseHandle failed";
    return;
  }
}
