
#define UNICODE
#include <windows.h>
#include <werapi.h>
#include <shlwapi.h>
#pragma comment(lib, "shlwapi.lib")

#include <stdio.h>

typedef HRESULT (WINAPI *_WerRegisterMemoryBlockWorker)(PVOID Address, ULONG Size);

int test(void) {
  return 0;
}

int main(void) {
    HRESULT hr;
    WCHAR   path[MAX_PATH];
    HMODULE m;
    PVOID ds;
    _WerRegisterMemoryBlockWorker = (_WerRegisterMemoryBlockWorker)GetProcAddress(
      GetModuleHandle(L"kernel32"), "WerRegisterMemoryBlockWorker");
    
    m = GetModuleHandle(L"kernel32");
    //ds = VirtualAlloc();
    
    hr = WerRegisterMemoryBlockWorker((PVOID)test, 32);
    
    GetModuleFileName (NULL, path, MAX_PATH);
    PathRemoveFileSpec(path);
    PathAppend(path, L"wermodule.dll");
    hr = WerRegisterRuntimeExceptionModule(path, NULL);

    GetModuleFileName (NULL, path, MAX_PATH);
    PathRemoveFileSpec(path);
    PathAppend(path, L"wermodule2.dll");
    hr = WerRegisterRuntimeExceptionModule(path, NULL);
    
    //WerRegisterMemoryBlockWorker
    
    getchar();
    //RaiseException (0xABCD1234, EXCEPTION_NONCONTINUABLE, 0, NULL);
    
    WerUnregisterRuntimeExceptionModule(path, NULL);
    return 0;
}
