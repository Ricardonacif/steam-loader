#include "Utils.h"

std::string GetLastErrorAsString() {
  //Get the error message, if any.
  DWORD errorMessageID = ::GetLastError();
  if (errorMessageID == 0)
    return std::string(); //No error message has been recorded

  LPSTR messageBuffer = nullptr;
  size_t size = FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
    NULL, errorMessageID, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR) & messageBuffer, 0, NULL);

  std::string message(messageBuffer, size);

  //Free the buffer.
  LocalFree(messageBuffer);

  return message;
}

void LogThis(const char * text) {
  std::cout << "--==-- " << text << " --==--\n";
}

char * TO_CHAR(wchar_t * string) {
  size_t len = wcslen(string) + 1;
  char * c_string = new char[len];
  size_t numCharsRead;
  wcstombs_s( & numCharsRead, c_string, len, string, _TRUNCATE);
  return c_string;
}

PEB * GetPEB() {
  #ifdef _WIN64
  PEB * peb = (PEB * ) __readgsword(0x60);

  #else
  PEB * peb = (PEB * ) __readfsdword(0x30);
  #endif

  return peb;
}

LDR_DATA_TABLE_ENTRY * GetLDREntry(std::string name) {
  LDR_DATA_TABLE_ENTRY * ldr = nullptr;

  PEB * peb = GetPEB();

  LIST_ENTRY head = peb -> Ldr -> InMemoryOrderModuleList;

  LIST_ENTRY curr = head;

  while (curr.Flink != head.Blink) {
    LDR_DATA_TABLE_ENTRY * mod = (LDR_DATA_TABLE_ENTRY * ) CONTAINING_RECORD(curr.Flink, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

    if (mod -> FullDllName.Buffer) {
      char * cName = TO_CHAR(mod -> BaseDllName.Buffer);

      if (_stricmp(cName, name.c_str()) == 0) {
        ldr = mod;
        break;
      }
      delete[] cName;
    }
    curr = * curr.Flink;
  }
  return ldr;
}

