#define WIN32_LEAN_AND_MEAN
#define UNICODE
#include <windows.h>
#include <werapi.h>

#pragma comment(lib, "user32.lib")

// WER calls this function to determine whether the exception handler is claiming the crash.
__declspec(dllexport)
HRESULT WINAPI PfnWerRuntimeExceptionEvent(
  PVOID pContext,
  const PWER_RUNTIME_EXCEPTION_INFORMATION pExceptionInformation,
  BOOL *pbOwnershipClaimed,
  PWSTR pwszEventName,
  PDWORD pchSize,
  PDWORD pdwSignatureCount)
{
  *pbOwnershipClaimed = FALSE;
  return S_OK;
}

// WER can call this function multiple times to get the report parameters that uniquely describe the problem.
__declspec(dllexport)
HRESULT WINAPI PfnWerRuntimeExceptionEventSignature(
  PVOID pContext,
  const PWER_RUNTIME_EXCEPTION_INFORMATION pExceptionInformation,
  DWORD dwIndex,
  PWSTR pwszName,
  PDWORD pchName,
  PWSTR pwszValue,
  PDWORD pchValue)
{
  return S_OK;
}

// WER calls this function to let you customize the debugger launch options and launch string.
__declspec(dllexport)
HRESULT WINAPI PfnWerRuntimeExceptionDebuggerLaunch(
  PVOID pContext,
  const PWER_RUNTIME_EXCEPTION_INFORMATION pExceptionInformation,
  PBOOL pbIsCustomDebugger,
  PWSTR pwszDebuggerLaunch,
  PDWORD pchDebuggerLaunch,
  PBOOL pbIsDebuggerAutolaunch)
{
  *pbIsCustomDebugger = FALSE;
  return S_OK;
}

__declspec(dllexport)
BOOL WINAPI DllMain(HMODULE hModule,
                      DWORD ul_reason_for_call,
                      LPVOID lpReserved) {
  switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
      MessageBox(NULL, L"Hello, World!", L"WER Module", MB_OK);
      break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
      break;
  }
  return TRUE;
}
