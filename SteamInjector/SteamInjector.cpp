#include <iostream>

#include <windows.h>

#include <tchar.h>

#include <stdio.h>

#include <string>

#include "Utils.h"

#include <TlHelp32.h>

#include "ManualMapper.h"

#include <filesystem>  


const char * procName = "steam.exe";

HANDLE getSteamProcessHandle() {
  LogThis("Looking for Steam process");
  Sleep(1000);

  PROCESSENTRY32 PE32 {
    0
  };
  PE32.dwSize = sizeof(PE32);

  HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (hSnap == INVALID_HANDLE_VALUE) {
    DWORD Err = GetLastError();
    LogThis("CreateToolhelp32Snapshot failed!");
    LogThis(GetLastErrorAsString().c_str());
    return 0;
  }


  LPCSTR sk = "SOFTWARE\\SteamLoader";
  HKEY default_key;
  auto status = RegCreateKeyExA(HKEY_LOCAL_MACHINE, sk, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, NULL, &default_key, NULL); 
  if (status == ERROR_SUCCESS)
  {
      std::string path = "c:\\";
      status = RegSetValueExA(default_key, "DllPath", 0, REG_EXPAND_SZ, (LPCBYTE)path.c_str(), path.size() + 1);
      RegCloseKey(default_key);
  }

  DWORD PID = 0;
  BOOL bRet = Process32First(hSnap, & PE32);
  while (bRet) {
    // printf("%s\n",PE32.szExeFile );
    if (!strcmp(procName, PE32.szExeFile)) {

      PID = PE32.th32ProcessID;
      break;
    }
    bRet = Process32Next(hSnap, & PE32);
  }

  CloseHandle(hSnap);

  HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);
  if (!hProc) {
    DWORD Err = GetLastError();
    LogThis("OpenProcess failed!");
    LogThis(GetLastErrorAsString().c_str());
    return 0;
  }

  return hProc;
}


int main() {
  Sleep(10000);
  LogThis("Welcome to SteamLoader!");

  LogThis("=============================================");
  LogThis("Hacking into the mainframe and disabling it's algorithm.");
  Sleep(5000);

  HANDLE processHandle = getSteamProcessHandle();

  if (processHandle == NULL) {
    LogThis("Process handle failed. Exiting.");
    return 1;
  }

  LogThis("Found steam.exe. Now finding the dll to be injected.");
  Sleep(1000);
  
  std::filesystem::path currentPath = std::filesystem::current_path();  

  std::filesystem::path fullPath = (currentPath.parent_path() += _T("\\Release\\SteamDll.dll"));

  LPCSTR sk = "SOFTWARE\\SteamLoader";

  HKEY default_key;

  auto status = RegCreateKeyExA(HKEY_LOCAL_MACHINE, sk, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, NULL, &default_key, NULL); 
  if (status == ERROR_SUCCESS)
  {
      status = RegSetValueExA(default_key, "DllPath", 0, REG_EXPAND_SZ, (LPCBYTE)fullPath.string().c_str(), fullPath.string().size() + 1);
      RegCloseKey(default_key);
  }

  LogThis(fullPath.string().c_str());
  LogThis("The SteamDll.dll. Injecting.");
  LogThis(".");
  Sleep(2000);
  LogThis("..");
  Sleep(2000);
  LogThis("...");
  Sleep(3000);

  LogThis("You do realize that its doing nothing right now right? I just added these sleeps so we can get hyped up.");
  Sleep(4000);
  LogThis("Ok, now actual manual mapping the DLL into the process.");
  Sleep(2000);

  if (!ManualMap(processHandle, fullPath.string().c_str())) {
    printf("Something went wrong :(");
  } else {
    LogThis("Injected. Have fun!");
  }

  CloseHandle(processHandle);

}