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

// just read and write back a pointer
BOOL WriteAccess(HANDLE hp, LPVOID addr) {
    BOOL      bWrite;
    ULONG_PTR p;
    SIZE_T    len;
    
    // read
    bWrite = ReadProcessMemory(hp, addr, &p, sizeof(p), &len);
    if(bWrite && len == sizeof(p)) {
      // write
      bWrite = WriteProcessMemory(hp, addr, &p, sizeof(p), &len);
    }
    return bWrite;
}

VOID ScanProcess(DWORD pid, LPWSTR name) {
    HANDLE                   hProcess;
    SYSTEM_INFO              si;
    MEMORY_BASIC_INFORMATION mbi;
    LPBYTE                   addr;     // current address
    SIZE_T                   res;
    BYTE                     buffer[sizeof(SYMBOL_INFO)+MAX_SYM_NAME*sizeof(WCHAR)];
    PSYMBOL_INFO             pSymbol=(PSYMBOL_INFO)buffer;
    
    hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    
    if (hProcess != NULL) {
      SymInitialize(hProcess, NULL, TRUE);
      GetSystemInfo(&si);
      
      for (addr=0; addr < (LPBYTE)si.lpMaximumApplicationAddress;) {
        ZeroMemory(&mbi, sizeof(mbi));
        res = VirtualQueryEx(hProcess, addr, &mbi, sizeof(mbi));
        if(res != sizeof(mbi)) break;
        
        if(mbi.Protect == PAGE_EXECUTE_READWRITE) {
          // do we have write access to this executable area of memory?
          if(WriteAccess(hProcess, mbi.BaseAddress)) {
            // show the process, address and size of cave
            wprintf(L"RWX : %-20ws : %p : %zi\n", 
              name, mbi.BaseAddress, mbi.RegionSize);
          }
        }
        if(mbi.Type == MEM_IMAGE) {
          wprintf(L"RX : %-20ws : %p : %zi\n", 
            name, mbi.BaseAddress, mbi.RegionSize);          
        }
        addr = (PBYTE)mbi.BaseAddress + mbi.RegionSize;
      }
      SymCleanup(hProcess);
      CloseHandle(hProcess);
    }
}

VOID ScanSystem(DWORD pid) {
    HANDLE         hSnap;
    PROCESSENTRY32 pe32;
    BOOL           bFound=FALSE;
    
    hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if(hSnap == INVALID_HANDLE_VALUE) return;
    
    pe32.dwSize = sizeof(PROCESSENTRY32);

    if(Process32First(hSnap, &pe32)){
      do {
        if(pid != 0 && pe32.th32ProcessID != pid) continue;
        ScanProcess(pe32.th32ProcessID, pe32.szExeFile);
      } while(Process32Next(hSnap, &pe32));
    }
    CloseHandle(hSnap);
}

int main(void) {
    PWCHAR *argv;
    int    argc;
    DWORD  pid = 0;
    
    argv = CommandLineToArgvW(GetCommandLine(), &argc);
    
    SetPrivilege(SE_DEBUG_NAME, TRUE);

    if(argc == 2) {
      pid = name2pid(argv[1]);
      if(pid == 0) pid = _wtoi(argv[1]);
      if(pid == 0) {
        printf("unable to resolve pid for \"%ws\"\n", argv[1]);
        return 0;
      }
    }
    SymSetOptions(SYMOPT_DEFERRED_LOADS);
    ScanSystem(pid);
    return 0;
}
