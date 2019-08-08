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

// Relative Virtual Address to Virtual Address
#define RVA2VA(type, base, rva) (type)((ULONG_PTR) base + rva)

// does the pointer reside in the .code section?
BOOL IsCodePtrEx(HANDLE hp, LPVOID ptr) {
    MEMORY_BASIC_INFORMATION mbi;
    DWORD                    res;
    
    if(ptr == NULL) return FALSE;
    
    // query the pointer
    res = VirtualQueryEx(hp, ptr, &mbi, sizeof(mbi));
    if(res != sizeof(mbi)) return FALSE;

    return ((mbi.State   == MEM_COMMIT    ) &&
            (mbi.Type    == MEM_IMAGE     ) && 
            (mbi.Protect == PAGE_EXECUTE_READ));
}

// does pointer reside on the stack or heap?
BOOL IsHeapPtrEx(HANDLE hp, LPVOID ptr) {
    MEMORY_BASIC_INFORMATION mbi;
    DWORD                    res;
    
    if(ptr == NULL) return FALSE;
    
    // query the pointer
    res = VirtualQueryEx(hp, ptr, &mbi, sizeof(mbi));
    if(res != sizeof(mbi)) return FALSE;

    return ((mbi.State   == MEM_COMMIT    ) &&
            (mbi.Type    == MEM_PRIVATE   ) && 
            (mbi.Protect == PAGE_READWRITE));
}

// does pointer reside in the .data section?
BOOL IsDataPtrEx(HANDLE hp, LPVOID ptr) {
    MEMORY_BASIC_INFORMATION mbi;
    DWORD                    res;
    
    if(ptr == NULL) return FALSE;
    
    // query the pointer
    res = VirtualQueryEx(hp, ptr, &mbi, sizeof(mbi));
    if(res != sizeof(mbi)) return FALSE;

    return ((mbi.State   == MEM_COMMIT    ) &&
            (mbi.Type    == MEM_IMAGE     ) && 
            (mbi.Protect == PAGE_READWRITE));
}

#include "mpr.h"
#include "npapi.h"
#include "mprdata.h"

BOOL ValidateMPR(HANDLE hp, LPVOID cs) {
    PROVIDER prov;
    SIZE_T   rd;
    
    // read provider
    if(!ReadProcessMemory(hp, cs, &prov, 
      sizeof(prov), &rd)) return FALSE;
    
    // valid scope?
    switch(prov.Resource.dwScope) {
      case RESOURCE_CONNECTED :
      case RESOURCE_GLOBALNET :
      case RESOURCE_CONTEXT   :
        break;
      default:
        return FALSE;
    }
    
    /// valid type?
    switch(prov.Resource.dwType) {
      case RESOURCETYPE_DISK  :
      case RESOURCETYPE_PRINT :
      case RESOURCETYPE_ANY   :
        break;
      default:
        return FALSE;
    }    

    // valid display type?
    switch(prov.Resource.dwDisplayType) {
      case RESOURCEDISPLAYTYPE_NETWORK   :
      case RESOURCEDISPLAYTYPE_DOMAIN    :
      case RESOURCEDISPLAYTYPE_SERVER    :
      case RESOURCEDISPLAYTYPE_SHARE     :
      case RESOURCEDISPLAYTYPE_DIRECTORY :
      case RESOURCEDISPLAYTYPE_GENERIC   :
        break;
      default:
        return FALSE;
    }
    
    // if not empty, make sure it's the heap
    if(prov.Resource.lpLocalName != NULL) {
      if(!IsHeapPtrEx(hp, prov.Resource.lpLocalName)) 
        return FALSE;
    }
    
    if(prov.Resource.lpRemoteName != NULL) {
      if(!IsHeapPtrEx(hp, prov.Resource.lpRemoteName)) 
        return FALSE;
    }
    
    if(prov.Resource.lpComment != NULL) {
      if(!IsHeapPtrEx(hp, prov.Resource.lpComment)) 
        return FALSE;
    }
    
    if(prov.Resource.lpProvider != NULL) {
      if(!IsHeapPtrEx(hp, prov.Resource.lpProvider)) 
        return FALSE;
    }
    
    // ensure at least one function points to code
    if(!IsCodePtrEx(hp, prov.AddConnection)) 
      return FALSE;
    
    return TRUE;
}

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

#define UNICODE
#define SECURITY_WIN32

#include <schannel.h>
#include <security.h>
#include <sspi.h>

DWORD ListCodePtr(HANDLE hp, PWCHAR dll, PLDR_DATA_TABLE_ENTRY dte) {
    WCHAR                 path[MAX_PATH];
    SIZE_T                rd;
    LPVOID                cs, m;
    PIMAGE_DOS_HEADER     dos;
    PIMAGE_NT_HEADERS     nt;
    PIMAGE_SECTION_HEADER sh;
    DWORD                 i, ptrs=0, cnt, rva=0;
    PULONG_PTR            ds, ptr;
    BOOL                  bRead;
    SecurityFunctionTableW sspi;
    
    if(ReadProcessMemory(hp, dte->FullDllName.Buffer, path, MAX_PATH, &rd)) {
      // if DLL specified and this doesn't match ours, return
      if(dll != NULL && StrStrI(path, dll) == NULL) return 0;
      
      m = GetModuleHandle(path);
      if(m == NULL) {
        m = LoadLibrary(path);
        if(m == NULL) {
          printf("Unable to load %ws\n", path);
          return 0;
        }
      }
      dos = (PIMAGE_DOS_HEADER)m;  
      nt  = RVA2VA(PIMAGE_NT_HEADERS, m, dos->e_lfanew);  
      sh  = (PIMAGE_SECTION_HEADER)((LPBYTE)&nt->OptionalHeader + 
          nt->FileHeader.SizeOfOptionalHeader);
          
      // locate the .data segment, save va and number of pointers
      for(i=0; i<nt->FileHeader.NumberOfSections; i++) {
        if(*(PDWORD)sh[i].Name == *(PDWORD)".data") {
          ds  = RVA2VA(PULONG_PTR, dte->DllBase, sh[i].VirtualAddress);
          cnt = sh[i].Misc.VirtualSize / sizeof(ULONG_PTR);
          break;
        }
      }
      
      // for each pointer
      for(ptrs=i=0; i<cnt; i++) {
        // read a pointer
        //printf("Reading %p\n", &ds[i]);
        bRead = ReadProcessMemory(hp, &ds[i], &cs, sizeof(ULONG_PTR), &rd);
        if(!bRead) break;
        if(cs == NULL) continue;
        
        // code pointer?
        if(IsHeapPtrEx(hp, cs)) {
          ptrs++;
         // printf("Reading SSPI structure from %p.\n", cs);
          ReadProcessMemory(hp, cs, &sspi, sizeof(sspi), &rd);
          //printf("Checking %p\n", sspi.EnumerateSecurityPackagesW);
          if(IsCodePtrEx(hp, sspi.EnumerateSecurityPackagesW)  &&
             IsCodePtrEx(hp, sspi.QueryCredentialsAttributesW) &&
             IsCodePtrEx(hp, sspi.AcquireCredentialsHandleW))
          {
         // if(ValidateMPR(hp, cs)) {
            printf("%ws\n", path);
            printf("    %p => ", &ds[i]);
            printf("%p : %ws\n", cs, addr2sym(hp, cs));
         // }
          }
        }
      }
    }
    return ptrs;
}

VOID EnumCodePtr(PPROCESSENTRY32 pe32, PWCHAR dll) {
    HANDLE                    hp;
    DWORD                     i, total;
    PROCESS_BASIC_INFORMATION pbi;
    NTSTATUS                  status;
    PEB                       peb;
    SIZE_T                    rd;
    PEB_LDR_DATA              ldr;
    PLIST_ENTRY               head, curr;
    LDR_DATA_TABLE_ENTRY      dte;
    BOOL                      bRead;
    WCHAR                     path[MAX_PATH];
    
    // try open the process
    hp = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe32->th32ProcessID);
    
    if(hp == NULL) {
      printf("Unable to open %ws:%lu\n", pe32->szExeFile, GetLastError());
      return;
    }
    
    printf("**********************************************************\n");
    printf("Checking %ws : %lu\n", pe32->szExeFile, pe32->th32ProcessID);
    
    SymSetOptions(SYMOPT_DEFERRED_LOADS);
    SymInitialize(hp, NULL, TRUE);
    
    status = NtQueryInformationProcess(hp, 
      ProcessBasicInformation, &pbi, sizeof(pbi), NULL);
      
    if(NT_SUCCESS(status)) {
      // try reading the PEB into local memory
      if(ReadProcessMemory(hp, pbi.PebBaseAddress, &peb, sizeof(peb), &rd)) {
        // try reading the PEB_LDR_DATA into local memory
        if(ReadProcessMemory(hp, peb.Ldr, &ldr, sizeof(ldr), &rd)) {
          // for each DLL
          head = (PLIST_ENTRY)ldr.InLoadOrderModuleList.Flink;
          curr = (PLIST_ENTRY)ldr.InLoadOrderModuleList.Flink;
          
          for(total=0;;) {
            bRead = ReadProcessMemory(hp, curr, &dte, sizeof(dte), &rd);
            if(!bRead || rd != sizeof(dte)) break;
            
            total += ListCodePtr(hp, dll, &dte);
            
            curr = dte.InLoadOrderLinks.Flink;
            if(curr == head) break;
          }
        }
      }
    }
    if(total != 0) {
      printf("\nFound %i code pointers.\n", total);
    }
    SymCleanup(hp);
    CloseHandle(hp);
}

VOID ScanProcess(DWORD pid, PWCHAR dll) {
    HANDLE         hs;
    PROCESSENTRY32 pe32;
   
    hs = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if(hs == INVALID_HANDLE_VALUE) return;
    
    pe32.dwSize = sizeof(PROCESSENTRY32);

    if(Process32First(hs, &pe32)){
      do {
        // if filtering by pid, skip if not our pid
        if(pid != 0 && pe32.th32ProcessID != pid) continue;
        // if not filtering by pid, don't list pointers in ourselves
        if(pe32.th32ProcessID == GetCurrentProcessId()) continue;
        
        EnumCodePtr(&pe32, dll);
      } while(Process32Next(hs, &pe32));
    }
    CloseHandle(hs);
}

void SSPIGetRVA(void) {
    HMODULE m = LoadLibrary(L"sspicli");
    
    
}

#include <knownfolders.h>
#include <shlobj.h>
#include <shlwapi.h>

int main(void) {
    DWORD   i, j, len, cnt, pid = 0;
    LPVOID  payload;
    int     argc;
    wchar_t **argv, *process = NULL, *dll = NULL;

    // try enable debug privilege
    if(!SetPrivilege(SE_DEBUG_NAME, TRUE)) {
      printf("WARNING: could not enable debugging privilege.\n");
    }
    
    argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    
    for(i=1; i<argc; i++) {
      if(argv[i][0]=='/' || argv[i][0]=='-') {
        switch(argv[i][1]) {
          case L'm':
            dll = argv[++i];
            break;
          default:
            printf("unknown switch : %c\n", argv[i][1]);
            break;
        }
      } else {
        process = argv[i];
      }
    }

    if(process != NULL) {
      pid = name2pid(process);
      if(pid == 0) pid = wcstoull(process, NULL, 10);
      if(pid == 0) {
        printf("ERROR: unable to resolve pid for \"%ws\".\n", process);
        return -1;
      }
    }
    printf("Checking %ws for %ws.\n",
      pid != 0    ? pid2name(pid) : L"all processes",
      dll != NULL ? dll           : L"all DLL");
      
    ScanProcess(pid, dll);
    return 0;
}
