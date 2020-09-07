// dllmain.cpp : Defines the entry point for the DLL application.
#include <iostream>

#include <iomanip>

#include <windows.h>

#include <tlhelp32.h>

#include <tchar.h>

#include "../SteamInjector/Utils.h"

#include "../SteamInjector/ManualMapper.h"

#include "DetourXS/detourxs.h"

#pragma warning(disable:4996)


char gameDllPath[_MAX_PATH];

typedef BOOL(WINAPI * tCreateProcessW)(
  LPCTSTR lpApplicationName,
  LPTSTR lpCommandLine,
  LPSECURITY_ATTRIBUTES lpProcessAttributes,
  LPSECURITY_ATTRIBUTES lpThreadAttributes,
  BOOL bInheritHandles,
  DWORD dwCreationFlags,
  LPVOID lpEnvironment,
  LPCTSTR lpCurrentDirectory,
  LPSTARTUPINFOW lpStartupInfo,
  LPPROCESS_INFORMATION lpProcessInformation
);

typedef BOOL(WINAPI * tCreateProcessA)(
  LPCSTR lpApplicationName,
  LPSTR lpCommandLine,
  LPSECURITY_ATTRIBUTES lpProcessAttributes,
  LPSECURITY_ATTRIBUTES lpThreadAttributes,
  BOOL bInheritHandles,
  DWORD dwCreationFlags,
  LPVOID lpEnvironment,
  LPCSTR lpCurrentDirectory,
  LPSTARTUPINFOA lpStartupInfo,
  LPPROCESS_INFORMATION lpProcessInformation
);

typedef BOOL(WINAPI * tNtSetInformationThread)(
  HANDLE ThreadHandle,
  ULONG ThreadInformationClass,
  PVOID ThreadInformation,
  ULONG ThreadInformationLength
);

char modulePath[_MAX_PATH];
tCreateProcessW originalCreateProcessW;
tCreateProcessA originalCreateProcessA;
tNtSetInformationThread originalNtSetInformationThread;

void manualMapDllAndResumeThread(LPPROCESS_INFORMATION lpProcessInformation,
  const char * gameDllPath, bool shouldResumeThread, bool shouldSkipInjection) {
  if (!shouldSkipInjection) {
    if (ManualMap(lpProcessInformation -> hProcess, gameDllPath)) {
      //lets give it sometime to do its thing.
      Sleep(3000);
    }
  }

  if (shouldResumeThread) {
    // Resume application
    ResumeThread(lpProcessInformation -> hThread);
  }
}

BOOL WINAPI hookedCreateProcessA(
  LPCSTR lpApplicationName,
  LPSTR lpCommandLine,
  LPSECURITY_ATTRIBUTES lpProcessAttributes,
  LPSECURITY_ATTRIBUTES lpThreadAttributes,
  BOOL bInheritHandles,
  DWORD dwCreationFlags,
  LPVOID lpEnvironment,
  LPCSTR lpCurrentDirectory,
  LPSTARTUPINFOA lpStartupInfo,
  LPPROCESS_INFORMATION lpProcessInformation
) {
  bool isProcessSupposedToStartSuspended = (dwCreationFlags & CREATE_SUSPENDED) != 0;

  dwCreationFlags |= CREATE_SUSPENDED;

  BOOL processCreateSucceeded = originalCreateProcessA(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);

  if (processCreateSucceeded) {
    manualMapDllAndResumeThread(lpProcessInformation, (const char*)gameDllPath, !isProcessSupposedToStartSuspended, false);
  }

  return processCreateSucceeded;
}

BOOL WINAPI hookedCreateProcessW(
  LPCTSTR lpApplicationName,
  LPTSTR lpCommandLine,
  LPSECURITY_ATTRIBUTES lpProcessAttributes,
  LPSECURITY_ATTRIBUTES lpThreadAttributes,
  BOOL bInheritHandles,
  DWORD dwCreationFlags,
  LPVOID lpEnvironment,
  LPCTSTR lpCurrentDirectory,
  LPSTARTUPINFOW lpStartupInfo,
  LPPROCESS_INFORMATION lpProcessInformation
) {

  bool shouldSkipInjection = false;

  if (lpCommandLine != NULL) {
    // just because we can doesn't mean we should right?
    if (_tcsstr(lpCommandLine, _T("GameOverlayUI.exe"))) {
      shouldSkipInjection = true;
    }
  }

  bool isProcessSupposedToStartSuspended = (dwCreationFlags & CREATE_SUSPENDED) != 0;

  dwCreationFlags |= CREATE_SUSPENDED;

  BOOL processCreateSucceeded = originalCreateProcessW(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);

  if (processCreateSucceeded) {
    manualMapDllAndResumeThread(lpProcessInformation, (const char*)gameDllPath, !isProcessSupposedToStartSuspended, shouldSkipInjection);
  }

  return processCreateSucceeded;
}

BOOL WINAPI hookNtSetInformationThread(
  HANDLE ThreadHandle,
  ULONG ThreadInformationClass,
  PVOID ThreadInformation,
  ULONG ThreadInformationLength
) {

  // Ignore the ThreadHideFromDebugger flag
  if (ThreadInformationClass == 0x11) {
    return TRUE;
  }

  return originalNtSetInformationThread(ThreadHandle, ThreadInformationClass, ThreadInformation, ThreadInformationLength);
}

DetourXS * detourCreateProcessA = NULL;
DetourXS * detourCreateProcessW = NULL;
DetourXS * detourNtSetInformationThread = NULL;

int WINAPI GameProcessOpenerHook(HMODULE hModule) {
  // AllocConsole();
  // FILE * f;
  // freopen_s( & f, "CONOUT$", "w", stdout);


  LPCSTR sk = "SOFTWARE\\SteamLoader";
  std::string str_data;
  DWORD size = 0;
  
  const DWORD dwFlags = RRF_RT_REG_EXPAND_SZ | RRF_NOEXPAND;
  auto status = RegGetValueA(HKEY_LOCAL_MACHINE, sk, "DllPath", dwFlags, NULL, NULL, &size);

  std::cout << str_data << std::endl;
  if ((status == ERROR_SUCCESS) && (size > 1))
  {
      str_data.resize(size - 1);
      status = RegGetValueA(HKEY_LOCAL_MACHINE, sk, "DllPath", dwFlags, NULL, &str_data[0], &size);
  }

  strncpy(gameDllPath, str_data.c_str(), sizeof(gameDllPath));
  gameDllPath[sizeof(gameDllPath) - 1] = 0;


  GetModuleFileNameA(hModule, modulePath, sizeof(modulePath));

  tNtSetInformationThread NtSetInformationThread = (tNtSetInformationThread) GetProcAddress(GetModuleHandle(TEXT("ntdll.dll")), "ZwSetInformationThread");

  detourCreateProcessW = new DetourXS( & CreateProcessW, hookedCreateProcessW);
  originalCreateProcessW = (tCreateProcessW) detourCreateProcessW -> GetTrampoline();

  detourNtSetInformationThread = new DetourXS((LPVOID) NtSetInformationThread, hookNtSetInformationThread);
  originalNtSetInformationThread = (tNtSetInformationThread) detourNtSetInformationThread -> GetTrampoline();

  // Sleep(999999999000);

  // fclose(f);
  // FreeConsole();
  FreeLibraryAndExitThread(hModule, 0);
  return 0;
};

BOOL APIENTRY DllMain(HMODULE hModule,
  DWORD ul_reason_for_call,
  LPVOID lpReserved) {
  switch (ul_reason_for_call) {
  case DLL_PROCESS_ATTACH:
    CloseHandle(CreateThread(nullptr, 0, (LPTHREAD_START_ROUTINE) GameProcessOpenerHook, hModule, 0, nullptr));
  case DLL_THREAD_ATTACH:
  case DLL_THREAD_DETACH:
  case DLL_PROCESS_DETACH:
    break;
  }
  return TRUE;
}