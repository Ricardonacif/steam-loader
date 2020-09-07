#pragma once

#include <iostream>

#include <string>

#include <windows.h>

#include <tlhelp32.h>

typedef struct _UNICODE_STRING {
  USHORT Length;
  USHORT MaximumLength;
  PWSTR Buffer;
}
UNICODE_STRING, * PUNICODE_STRING;

typedef struct _PEB_LDR_DATA {
  BYTE Reserved1[8];
  PVOID Reserved2[3];
  LIST_ENTRY InMemoryOrderModuleList;
}
PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _RTL_USER_PROCESS_PARAMETERS {
  BYTE Reserved1[16];
  PVOID Reserved2[10];
  UNICODE_STRING ImagePathName;
  UNICODE_STRING CommandLine;
}
RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;

typedef struct _PEB {
  BYTE Reserved1[2];
  BYTE BeingDebugged;
  BYTE Reserved2[1];
  PVOID Reserved3[2];
  PPEB_LDR_DATA Ldr;
  PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
  PVOID Reserved4[3];
  PVOID AtlThunkSListPtr;
  PVOID Reserved5;
  ULONG Reserved6;
  PVOID Reserved7;
  ULONG Reserved8;
  ULONG AtlThunkSListPtr32;
  PVOID Reserved9[45];
  BYTE Reserved10[96];
  PVOID PostProcessInitRoutine;
  BYTE Reserved11[128];
  PVOID Reserved12[1];
  ULONG SessionId;
}
PEB, * PPEB;

typedef struct _LDR_DATA_TABLE_ENTRY {
  LIST_ENTRY InLoadOrderLinks; /* 0x00 */
  LIST_ENTRY InMemoryOrderLinks; /* 0x08 */
  LIST_ENTRY InInitializationOrderLinks; /* 0x10 */
  PVOID DllBase; /* 0x18 */
  PVOID EntryPoint;
  ULONG SizeOfImage;
  UNICODE_STRING FullDllName; /* 0x24 */
  UNICODE_STRING BaseDllName; /* 0x28 */
  ULONG Flags;
  WORD LoadCount;
  WORD TlsIndex;
  union {
    LIST_ENTRY HashLinks;
    struct {
      PVOID SectionPointer;
      ULONG CheckSum;
    };
  };
  union {
    ULONG TimeDateStamp;
    PVOID LoadedImports;
  };
  _ACTIVATION_CONTEXT * EntryPointActivationContext;
  PVOID PatchInformation;
  LIST_ENTRY ForwarderLinks;
  LIST_ENTRY ServiceTagLinks;
  LIST_ENTRY StaticLinks;
}
LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

std::string GetLastErrorAsString();
void LogThis(const char * text);
char * TO_CHAR(wchar_t * string);
PEB * GetPEB();
LDR_DATA_TABLE_ENTRY * GetLDREntry(std::string name);