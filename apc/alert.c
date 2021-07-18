/**
  Copyright © 2019 Odzhan. All Rights Reserved.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions are
  met:

  1. Redistributions of source code must retain the above copyright
  notice, this list of conditions and the following disclaimer.

  2. Redistributions in binary form must reproduce the above copyright
  notice, this list of conditions and the following disclaimer in the
  documentation and/or other materials provided with the distribution.

  3. The name of the author may not be used to endorse or promote products
  derived from this software without specific prior written permission.

  THIS SOFTWARE IS PROVIDED BY AUTHORS "AS IS" AND ANY EXPRESS OR
  IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
  DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
  INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
  (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
  HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
  STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
  ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
  POSSIBILITY OF SUCH DAMAGE. */
  
/**
  Example output on Windows 10

  PC: 00007FFF1491C6E4 ntdll.dll!ZwDelayExecution
  Queuing APC for SleepEx.
  SleepEx ended

  PC: 00007FFF1491C0E4 ntdll.dll!NtWaitForSingleObject
  Queuing APC for WaitForSingleObjectEx.
  WaitForSingleObjectEx ended

  PC: 00007FFF1491CBB4 ntdll.dll!NtWaitForMultipleObjects
  Queuing APC for WaitForMultipleObjectsEx.
  WaitForMultipleObjectsEx ended

  PC: 00007FFF1491F654 ntdll.dll!NtSignalAndWaitForSingleObject
  Queuing APC for SignalObjectAndWait.
  SignalObjectAndWait ended

  PC: 00007FFF126C9A84 win32u.dll!NtUserMsgWaitForMultipleObjectsEx
  Queuing APC for MsgWaitForMultipleObjectsEx.
  MsgWaitForMultipleObjectsEx ended

  PC: 00007FFF1491CBB4 ntdll.dll!NtWaitForMultipleObjects
  Queuing APC for WSAWaitForMultipleEvents.
  WSAWaitForMultipleEvents ended

  PC: 00007FFF1491ED94 ntdll.dll!NtRemoveIoCompletionEx
  Queuing APC for GetQueuedCompletionStatusEx.
  GetQueuedCompletionStatusEx ended

  PC: 00007FFF1491C0E4 ntdll.dll!NtWaitForSingleObject
  Queuing APC for GetOverlappedResultEx.
  GetOverlappedResultEx ended

*/

#define UNICODE

#include <windows.h>
#include <dbghelp.h>
#include <shlwapi.h>
#include <psapi.h>
#include <stdio.h>
#include <wchar.h>
#include <wct.h>

#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "dbghelp.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "ws2_32.lib")

// resolve symbol for addr without using SymFromName
PWCHAR addr2sym(HANDLE hp, LPVOID addr) {
    WCHAR        path[MAX_PATH];
    BYTE         buf[sizeof(SYMBOL_INFO)+MAX_SYM_NAME*sizeof(WCHAR)];
    PSYMBOL_INFO si=(PSYMBOL_INFO)buf;
    static WCHAR name[MAX_PATH];
    
    ZeroMemory(path, ARRAYSIZE(path));
    ZeroMemory(name, ARRAYSIZE(name));
          
    GetMappedFileName(
      hp, addr, path, MAX_PATH);
    
    PathStripPath(path);
    
    si->SizeOfStruct = sizeof(SYMBOL_INFO);
    si->MaxNameLen   = MAX_SYM_NAME;
    
    if(SymFromAddr(hp, (DWORD64)addr, NULL, si)) {
      wsprintf(name, L"%s!%hs", path, si->Name);
    } else {
      lstrcpy(name, path);
    }
    return name;
}

DWORD WINAPI ThreadProc(LPVOID lpParameter) {
    HANDLE           port, *evt = (HANDLE)lpParameter;
    OVERLAPPED       lap;
    OVERLAPPED_ENTRY lapentry;
    ULONG            ulNumEntriesRemoved;
    
    // 1.
    SleepEx(0x12345678, TRUE);
    printf("SleepEx ended\n");

    // 2.
    WaitForSingleObjectEx(evt[0], 0x12345678, TRUE);
    printf("WaitForSingleObjectEx ended\n");

    // 3.
    WaitForMultipleObjectsEx(2, evt, FALSE, 0x12345678, TRUE);
    printf("WaitForMultipleObjectsEx ended\n");

    // 4.
    SignalObjectAndWait(evt[1], evt[0], 0x12345678, TRUE);
    printf("SignalObjectAndWait ended\n");

    // 5.
    ResetEvent(evt[0]);
    ResetEvent(evt[1]);
    MsgWaitForMultipleObjectsEx(2, evt, 
      0x12345678, QS_RAWINPUT, MWMO_ALERTABLE);
    printf("MsgWaitForMultipleObjectsEx ended\n");

    // 6.
    WSAWaitForMultipleEvents(2, evt, FALSE, 0x12345678, TRUE);
    printf("WSAWaitForMultipleEvents ended\n");
    
    // 7.
    port = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
    GetQueuedCompletionStatusEx(port, &lapentry, 1, 
      &ulNumEntriesRemoved, INFINITE, TRUE);
    printf("GetQueuedCompletionStatusEx ended\n");
    CloseHandle(port);
    
    // 8.
    ZeroMemory(&lap, sizeof(lap));
    lap.hEvent = evt[0];
    GetOverlappedResultEx(evt[2], &lap, NULL, 0x12345678, TRUE);
    printf("GetOverlappedResultEx ended\n");
    
    return 0;
}

int main(void) {  
    HANDLE              ht, h[3];
    LPVOID              m, f;
    DWORD               i;
    CONTEXT             c;
    
    char *api[8]={
      "SleepEx", 
      "WaitForSingleObjectEx",
      "WaitForMultipleObjectsEx",
      "SignalObjectAndWait",
      "MsgWaitForMultipleObjectsEx",
      "WSAWaitForMultipleEvents",
      "GetQueuedCompletionStatusEx",
      "GetOverlappedResultEx"};
    
    h[0] = CreateEvent(NULL, FALSE, FALSE, NULL);
    h[1] = CreateEvent(NULL, FALSE, FALSE, NULL);
    h[2] = CreateFile(L"alert.exe", GENERIC_READ, 
      FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    // resolve address of SetEvent 
    f = GetProcAddress(GetModuleHandle(L"kernel32"), "SetEvent");
    ht = CreateThread(NULL, 0, ThreadProc, h, 0, NULL);
    
    SymSetOptions(SYMOPT_DEFERRED_LOADS);
    SymInitialize(GetCurrentProcess(), NULL, TRUE);
    
    for(i=0; i<sizeof(api)/sizeof(char*); i++) {
      //printf("Press any key to continue...\n");
      //getchar();
      Sleep(500);
      
      c.ContextFlags = CONTEXT_INTEGER | CONTEXT_CONTROL;
      GetThreadContext(ht, &c);
      printf("\nPC: %p %ws\n", 
        (LPVOID)c.Rip, addr2sym(GetCurrentProcess(), (LPVOID)c.Rip));
      printf("Queuing APC for %s.\n", api[i]);
      // queue APC for alertable thread
      QueueUserAPC(f, ht, (ULONG_PTR)h);
    }
    // wait for thread to end
    WaitForSingleObject(ht, INFINITE);
    // cleanup and exit
    SymCleanup(GetCurrentProcess());
    CloseHandle(ht);
    CloseHandle(h[0]);
    CloseHandle(h[1]);
    CloseHandle(h[2]);
    
    return 0;
}

