#ifndef UTILITY_SERIALIZATION_H
#define UTILITY_SERIALIZATION_H

#include "hannibal.h"


void WriteUint8(UINT8 **buffer, UINT8 value);
void WriteUint32(UINT8 **buffer, UINT32 value);
void WriteUint64(UINT8 **buffer, UINT64 value);

void WriteString(UINT8 **buffer, const char *str, BOOL include_null);
void WriteStringW(UINT8 **buffer, const wchar_t *wstr, BOOL include_null);

void WriteBytes(UINT8 **buffer, const char *str, int size);

UINT8 ReadUint8(UINT8 **buffer);
UINT32 ReadUint32(UINT8 **buffer);

UINT8* ReadBytes(UINT8 **buffer, UINT32 length);

PCHAR ReadString(UINT8 **buffer, UINT32 length);
PWCHAR ReadStringW(UINT8 **buffer, UINT32 length);

DWORD pic_htonl(DWORD hostlong);


#endif