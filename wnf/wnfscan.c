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

char *stateName2str(ULONG64 StateName);

VOID DumpWnfTable(HANDLE hProcess, LPVOID addr) {
    WNF_SUBSCRIPTION_TABLE wst;
    BOOL                   bRead;
    SIZE_T                 rd;
    
    bRead = ReadProcessMemory(hProcess, addr, &wst, sizeof(wst), &rd);
    if(bRead && rd == sizeof(wst)) {
      printf("\nFound WNF_SUBSCRIPTION_TABLE at %p\n\n", addr);

      printf("NamesTableEntry.Flink : %p\n", wst.NamesTableEntry.Flink);
      printf("NamesTableEntry.Blink : %p\n", wst.NamesTableEntry.Blink);
      putchar('\n');
    }
}
    
VOID DumpWnfUserSub(HANDLE hProcess, LPVOID addr) {
    WNF_USER_SUBSCRIPTION wus;
    BOOL                  bRead;
    SIZE_T                rd;
    WCHAR                 cbfile[MAX_PATH], ctfile[MAX_PATH];
    
    bRead = ReadProcessMemory(hProcess, addr, &wus, sizeof(wus), &rd);
    
    if(bRead && rd == sizeof(wus)) {
      printf("\nFound WNF_USER_SUBSCRIPTION at %p\n\n", addr);
      
      ZeroMemory(cbfile, ARRAYSIZE(cbfile));
      ZeroMemory(ctfile, ARRAYSIZE(ctfile));
      
      GetMappedFileName(hProcess, 
        (LPVOID)wus.Callback, cbfile, MAX_PATH);
      
      GetMappedFileName(hProcess, 
        (LPVOID)wus.Context, ctfile, MAX_PATH);
        
      //printf("SubscriptionsListEntry.Flink : %p\n", wus.SubscriptionsListEntry.Flink);
      //printf("SubscriptionsListEntry.Blink : %p\n", wus.SubscriptionsListEntry.Blink);
      printf("NameSubscription             : %p\n", wus.NameSubscription);
      printf("Callback                     : %p : %ws\n", wus.Callback, cbfile);
      printf("Context                      : %p : %ws\n", wus.Context,  ctfile);
      putchar('\n');
    }
}

VOID DumpWnfNameSub(HANDLE hProcess, LPVOID addr) {
    WNF_NAME_SUBSCRIPTION wns;
    BOOL                  bRead;
    SIZE_T                rd;
    WCHAR                 cbfile[MAX_PATH], ctfile[MAX_PATH];
    ULONG64               x;
    
    bRead = ReadProcessMemory(hProcess, addr, &wns, sizeof(wns), &rd);
    
    if(bRead && rd == sizeof(wns)) {
      //printf("\nFound WNF_NAME_SUBSCRIPTION at %p\n\n", addr);
        
      //printf("SubscriptionId        : %llx\n", wns.SubscriptionId);
      x = *(ULONG64*)&wns.StateName;
      printf("StateName             : %016llx (%s)\n", x, stateName2str(x));
      //printf("CurrentChangeStamp    : %p\n",   (LPVOID)wns.CurrentChangeStamp);
      //printf("NamesTableEntry.Flink : %p\n",   wns.NamesTableEntry.Flink);
      //printf("NamesTableEntry.Blink : %p\n",   wns.NamesTableEntry.Blink);
     // putchar('\n');
    }
}

VOID FindWnfData(HANDLE hProcess, LPVOID BaseAddress, SIZE_T RegionSize) {
    LPBYTE             addr = (LPBYTE)BaseAddress;
    SIZE_T             pos  = 0;
    BOOL               bRead;
    SIZE_T             rd;
    WNF_CONTEXT_HEADER hdr;
    
    for(;;) {  
      bRead = ReadProcessMemory(hProcess,
        addr + pos, &hdr, sizeof(hdr), &rd);

      if(!bRead || rd != sizeof(hdr)) break;

        // subscription table?
      if(hdr.NodeTypeCode == 0x911 && hdr.NodeByteSize == 0x60) {
        //DumpWnfTable(hProcess, addr + pos);
        pos += 0x60;
      } else if (hdr.NodeTypeCode == 0x912 && hdr.NodeByteSize == 0x98) {
        // name subscription?
        DumpWnfNameSub(hProcess, addr + pos);
        pos += 0x98;
      } else if (hdr.NodeTypeCode == 0x913 && hdr.NodeByteSize == 0x28) {
        // group?
        //printf("Found group at %p\n", addr + pos);
        pos += 0x28;
      } else if (hdr.NodeTypeCode == 0x914 && hdr.NodeByteSize == 0xA8) {
        // user subscription            
        //DumpWnfUserSub(hProcess, addr + pos);
        pos += 0xA8;
      } else {
        pos += sizeof(WNF_CONTEXT_HEADER);
      }
      if(pos >= (RegionSize - sizeof(hdr))) break;
    }
}

VOID ScanProcess(DWORD pid) {
    HANDLE                   hProcess;
    SYSTEM_INFO              si;
    MEMORY_BASIC_INFORMATION mbi;
    LPBYTE                   addr;     // current address
    SIZE_T                   res;
    
    hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    
    if (hProcess != NULL) {
      GetSystemInfo(&si);
      
      for (addr=0; addr < (LPBYTE)si.lpMaximumApplicationAddress;) {
        ZeroMemory(&mbi, sizeof(mbi));
        res = VirtualQueryEx(hProcess, addr, &mbi, sizeof(mbi));
        if(res != sizeof(mbi)) break;
        
        if ((mbi.State   == MEM_COMMIT)  &&
            (mbi.Type    == MEM_PRIVATE) && 
            (mbi.Protect == PAGE_READWRITE))  
        {
          FindWnfData(hProcess, mbi.BaseAddress, mbi.RegionSize);
        }
        addr = (PBYTE)mbi.BaseAddress + mbi.RegionSize;
      }
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
        printf("Checking %ws\n\n", pe32.szExeFile);
        ScanProcess(pe32.th32ProcessID);
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
    ScanSystem(pid);
    return 0;
}

char *stateName2str(ULONG64 StateName) {
    DWORD       i;
    static char *str = "N/A";
    
    for(i=0; WnfNameMap[i].Name != 0; i++) {
      if(WnfNameMap[i].StateName == StateName) {
        str = (char*)WnfNameMap[i].Name;
        break;
      }
    }
    return str;
}

