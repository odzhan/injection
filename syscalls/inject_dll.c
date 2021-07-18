/**
  Copyright © 2019-2020 Odzhan. All Rights Reserved.

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

#ifndef _WIN64
#error This code must be compiled with a 64-bit version of MSVC
#endif

// compile: cl inject_dll.c
//
#include <windows.h>
#include <tlhelp32.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "user32.lib")
#pragma warning(disable : 4047)

#define STATUS_SUCCESS 0
#define OBJ_CASE_INSENSITIVE 0x00000040L
#define FILE_OVERWRITE_IF 0x00000005
#define FILE_SYNCHRONOUS_IO_NONALERT 0x00000020
typedef LONG KPRIORITY;

#define InitializeObjectAttributes( i, o, a, r, s ) {    \
      (i)->Length = sizeof( OBJECT_ATTRIBUTES );         \
      (i)->RootDirectory = r;                            \
      (i)->Attributes = a;                               \
      (i)->ObjectName = o;                               \
      (i)->SecurityDescriptor = s;                       \
      (i)->SecurityQualityOfService = NULL;              \
   }

typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef const UNICODE_STRING* PCUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
	ULONG Length;
	HANDLE RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG Attributes;
	PVOID SecurityDescriptor;
	PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef struct _CLIENT_ID {
	PVOID UniqueProcess;
	PVOID UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

typedef enum _SYSTEM_INFORMATION_CLASS {
	SystemBasicInformation,
	SystemProcessorInformation,
	SystemPerformanceInformation,
	SystemTimeOfDayInformation,
	SystemPathInformation,
	SystemProcessInformation,
	SystemCallCountInformation,
	SystemDeviceInformation,
	SystemProcessorPerformanceInformation,
	SystemFlagsInformation,
	SystemCallTimeInformation,
	SystemModuleInformation
} SYSTEM_INFORMATION_CLASS, *PSYSTEM_INFORMATION_CLASS;

typedef struct _SYSTEM_PROCESSES {
	ULONG NextEntryDelta;
	ULONG ThreadCount;
	ULONG Reserved1[6];
	LARGE_INTEGER CreateTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER KernelTime;
	UNICODE_STRING ProcessName;
	KPRIORITY BasePriority;
	HANDLE ProcessId;
	HANDLE InheritedFromProcessId;
} SYSTEM_PROCESSES, *PSYSTEM_PROCESSES;

typedef struct _IO_STATUS_BLOCK
{
	union
	{
		LONG Status;
		PVOID Pointer;
	};
	ULONG Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;


typedef NTSTATUS (NTAPI *NtAllocateVirtualMemory_t)(
	HANDLE             ProcessHandle,
	PVOID             *BaseAddress,
	ULONG_PTR          ZeroBits,
	PSIZE_T            RegionSize,
	ULONG              AllocationType,
	ULONG              Protect);

typedef NTSTATUS (NTAPI *NtFreeVirtualMemory_t)(
	HANDLE             ProcessHandle,
	PVOID             *BaseAddress,
	IN OUT PSIZE_T     RegionSize,
	ULONG              FreeType);

typedef NTSTATUS (NTAPI *NtOpenProcess_t)(
	PHANDLE            ProcessHandle,
	ACCESS_MASK        DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PCLIENT_ID         ClientId);
  
typedef NTSTATUS (NTAPI *NtWriteVirtualMemory_t)(
	HANDLE             hProcess,
	PVOID              lpBaseAddress,
	PVOID              lpBuffer,
	SIZE_T             NumberOfBytesToRead,
	PSIZE_T            NumberOfBytesRead);
  
typedef NTSTATUS (NTAPI *NtCreateThreadEx_t) (
  PHANDLE            ThreadHandle, 
  ACCESS_MASK        DesiredAccess, 
  POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL, 
  HANDLE             ProcessHandle,
  PVOID              StartRoutine,
  PVOID              Argument OPTIONAL,
  ULONG              CreateFlags,
  ULONG_PTR          ZeroBits, 
  SIZE_T             StackSize OPTIONAL,
  SIZE_T             MaximumStackSize OPTIONAL, 
  PVOID              AttributeList OPTIONAL);
    
typedef NTSTATUS (NTAPI *NtWaitForSingleObject_t)(
  HANDLE             ObjectHandle,
  BOOLEAN            Alertable,
  PLARGE_INTEGER     TimeOut OPTIONAL); 
  
typedef NTSTATUS (NTAPI *NtClose_t)(
  HANDLE             ObjectHandle);
  
typedef struct _syscall_t {
    NtOpenProcess_t           NtOpenProcess;
    NtAllocateVirtualMemory_t NtAllocateVirtualMemory;
    NtWriteVirtualMemory_t    NtWriteVirtualMemory;
    NtCreateThreadEx_t        NtCreateThreadEx;
    NtWaitForSingleObject_t   NtWaitForSingleObject;
    NtFreeVirtualMemory_t     NtFreeVirtualMemory;
    NtClose_t                 NtClose;
} syscall_t;

ULONG64 rva2ofs(PIMAGE_NT_HEADERS nt, DWORD rva) {
    PIMAGE_SECTION_HEADER sh;
    int                   i;
    
    if(rva == 0) return -1;
    
    sh = (PIMAGE_SECTION_HEADER)((LPBYTE)&nt->OptionalHeader + 
           nt->FileHeader.SizeOfOptionalHeader);
    
    for(i = nt->FileHeader.NumberOfSections - 1; i >= 0; i--) {
      if(sh[i].VirtualAddress <= rva &&
        rva <= (DWORD)sh[i].VirtualAddress + sh[i].SizeOfRawData)
      {
        return sh[i].PointerToRawData + rva - sh[i].VirtualAddress;
      }
    }
    return -1;
}

LPVOID GetProcAddress2(LPBYTE hModule, LPCSTR lpProcName) {
    PIMAGE_DOS_HEADER       dos;
    PIMAGE_NT_HEADERS       nt;
    PIMAGE_SECTION_HEADER   sh;
    PIMAGE_DATA_DIRECTORY   dir;
    PIMAGE_EXPORT_DIRECTORY exp;
    DWORD                   rva, ofs, cnt, nos;
    PCHAR                   str;
    PDWORD                  adr, sym;
    PWORD                   ord;
    
    if(hModule == NULL || lpProcName == NULL) return NULL;
    
    dos = (PIMAGE_DOS_HEADER)hModule;
    nt  = (PIMAGE_NT_HEADERS)(hModule + dos->e_lfanew);
    dir = (PIMAGE_DATA_DIRECTORY)nt->OptionalHeader.DataDirectory;
    
    // no exports? exit
    rva = dir[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if(rva == 0) return NULL;
    
    ofs = rva2ofs(nt, rva);
    if(ofs == -1) return NULL;
    
    // no exported symbols? exit
    exp = (PIMAGE_EXPORT_DIRECTORY)(ofs + hModule);
    cnt = exp->NumberOfNames;
    if(cnt == 0) return NULL;
    
    // read the array containing address of api names
    ofs = rva2ofs(nt, exp->AddressOfNames);        
    if(ofs == -1) return NULL;
    sym = (PDWORD)(ofs + hModule);

    // read the array containing address of api
    ofs = rva2ofs(nt, exp->AddressOfFunctions);        
    if(ofs == -1) return NULL;
    adr = (PDWORD)(ofs + hModule);
    
    // read the array containing list of ordinals
    ofs = rva2ofs(nt, exp->AddressOfNameOrdinals);
    if(ofs == -1) return NULL;
    ord = (PWORD)(ofs + hModule);
    
    // scan symbol array for api string
    do {
      str = (PCHAR)(rva2ofs(nt, sym[cnt - 1]) + hModule);
      // found it?
      if(lstrcmp(str, lpProcName) == 0) {
        // return the address
        return (LPVOID)(rva2ofs(nt, adr[ord[cnt - 1]]) + hModule);
      }
    } while (--cnt);
    return NULL;
}

#define NTDLL_PATH "%SystemRoot%\\system32\\NTDLL.dll"

LPVOID GetSyscallStub(LPCSTR lpSyscallName) {
    HANDLE                        file = NULL, map = NULL;
    LPBYTE                        mem = NULL;
    LPVOID                        cs = NULL;
    PIMAGE_DOS_HEADER             dos;
    PIMAGE_NT_HEADERS             nt;
    PIMAGE_DATA_DIRECTORY         dir;
    PIMAGE_RUNTIME_FUNCTION_ENTRY rf;
    ULONG64                       ofs, start=0, end=0, addr;
    SIZE_T                        len;
    DWORD                         i, rva;
    CHAR                          path[MAX_PATH];
    
    ExpandEnvironmentStrings(NTDLL_PATH, path, MAX_PATH);
    
    // open file
    file = CreateFile(path, 
      GENERIC_READ, FILE_SHARE_READ, NULL, 
      OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
      
    if(file == INVALID_HANDLE_VALUE) { goto cleanup; }
    
    // create mapping
    map = CreateFileMapping(file, NULL, PAGE_READONLY, 0, 0, NULL);
    if(map == NULL) { goto cleanup; }
    
    // create view
    mem = (LPBYTE)MapViewOfFile(map, FILE_MAP_READ, 0, 0, 0);
    if(mem == NULL) { goto cleanup; }
    
    // try resolve address of system call
    addr = (ULONG64)GetProcAddress2(mem, lpSyscallName);
    if(addr == 0) { goto cleanup; }
    
    dos = (PIMAGE_DOS_HEADER)mem;
    nt  = (PIMAGE_NT_HEADERS)((PBYTE)mem + dos->e_lfanew);
    dir = (PIMAGE_DATA_DIRECTORY)nt->OptionalHeader.DataDirectory;
    
    // no exception directory? exit
    rva = dir[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress;
    if(rva == 0) { goto cleanup; }
    
    ofs = rva2ofs(nt, rva);
    if(ofs == -1) { goto cleanup; }
    
    rf = (PIMAGE_RUNTIME_FUNCTION_ENTRY)(ofs + mem);

    // for each runtime function (there might be a better way??)
    for(i=0; rf[i].BeginAddress != 0; i++) {
      // is it our system call?
      start = rva2ofs(nt, rf[i].BeginAddress) + (ULONG64)mem;
      if(start == addr) {
        // save the end and calculate length
        end = rva2ofs(nt, rf[i].EndAddress) + (ULONG64)mem;
        len = (SIZE_T) (end - start);

        // allocate RWX memory
        cs = VirtualAlloc(NULL, len, 
          MEM_COMMIT | MEM_RESERVE,
          PAGE_EXECUTE_READWRITE);
          
        if(cs != NULL) {
          // copy system call code stub to memory
          CopyMemory(cs, (const void*)start, len);
        }
        break;
      }
    }
    
cleanup:
    if(mem != NULL) UnmapViewOfFile(mem);
    if(map != NULL) CloseHandle(map);
    if(file != NULL) CloseHandle(file);
    
    // return pointer to code stub or NULL
    return cs;
}

BOOL EnablePrivilege(PCHAR szPrivilege){
    HANDLE           hToken;
    BOOL             bResult;
    LUID             luid;
    TOKEN_PRIVILEGES tp;

    // open token for current process
    bResult = OpenProcessToken(GetCurrentProcess(),
      TOKEN_ADJUST_PRIVILEGES, &hToken);
    
    if(!bResult) return FALSE;
    
    // lookup privilege
    bResult = LookupPrivilegeValue(NULL, szPrivilege, &luid);
    if(bResult){
      tp.PrivilegeCount           = 1;
      tp.Privileges[0].Luid       = luid;
      tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

      // adjust token
      AdjustTokenPrivileges(hToken, FALSE, &tp, 0, NULL, NULL);
      bResult = GetLastError() == ERROR_SUCCESS;
    }
    CloseHandle(hToken);
    return bResult;
}

// display error message for last error code
VOID xstrerror (PCHAR fmt, ...){
    PCHAR  error=NULL;
    va_list arglist;
    CHAR   buffer[1024];
    DWORD   dwError=GetLastError();
    
    va_start(arglist, fmt);
    vsnprintf(buffer, ARRAYSIZE(buffer), fmt, arglist);
    va_end (arglist);
    
    if (FormatMessage (
          FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
          NULL, dwError, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), 
          (LPSTR)&error, 0, NULL))
    {
      printf("  [ %s : %s\n", buffer, error);
      LocalFree (error);
    } else {
      printf("  [ %s error : %08lX\n", buffer, dwError);
    }
}

DWORD name2pid(PCHAR procName){
    HANDLE         hSnap;
    PROCESSENTRY32 pe32;
    DWORD          pid=0;
    
    // create snapshot of system
    hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if(hSnap == INVALID_HANDLE_VALUE) return 0;
    
    pe32.dwSize = sizeof(PROCESSENTRY32);

    // get first process
    if(Process32First(hSnap, &pe32)){
      do {
        if(!lstrcmpi(pe32.szExeFile, procName)){
          pid=pe32.th32ProcessID;
          break;
        }
      } while(Process32Next(hSnap, &pe32));
    }
    CloseHandle(hSnap);
    return pid;
}

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

typedef HMODULE (WINAPI *LoadLibrary_t)(LPCTSTR);

VOID inject_dll(syscall_t *syscall, DWORD pid, PCHAR path) {
    SIZE_T            wr;
    LoadLibrary_t     _LoadLibrary;
    HANDLE            hp = NULL, ht = NULL;
    LPVOID            ds=NULL;
    SIZE_T            path_len = lstrlen(path);
    NTSTATUS          nts;
    CLIENT_ID         cid = {0};
    OBJECT_ATTRIBUTES oa = {sizeof(oa)};
    LARGE_INTEGER     li;
    
    if(!IsElevated()) {
      printf("WARNING: You're running this application from a restricted process.\n");
    }
    
    EnablePrivilege(SE_DEBUG_NAME);
    
    printf("1. Opening process %i ...", pid);
    cid.UniqueProcess = pid;
    
    nts = syscall->NtOpenProcess(&hp, 
      PROCESS_ALL_ACCESS, &oa, &cid);
    
    if(nts >= 0) {
      path_len++;
      printf("OK\n2. Allocating read-write (RW) memory for %s ...", path);
      
      nts = syscall->NtAllocateVirtualMemory(
        hp, &ds, 0, &path_len, 
        MEM_COMMIT | MEM_RESERVE, 
        PAGE_READWRITE);
      
      if(nts >= 0) {    
        printf("OK\n3. Copying %s to remote process ...", path);
        nts = syscall->NtWriteVirtualMemory(hp, ds, path, path_len-1, &wr);
        
        if(nts >= 0) {
          printf("OK\n4. Resolving the address of LoadLibrary.\n");
          _LoadLibrary = (LoadLibrary_t)GetProcAddress(
            GetModuleHandle("kernel32"), "LoadLibraryA");
        
          printf("5. Executing LoadLibrary in remote process..."); 
          // with DLL path as parameter
          nts = syscall->NtCreateThreadEx(
            &ht, MAXIMUM_ALLOWED, NULL, 
            hp, (LPTHREAD_START_ROUTINE)_LoadLibrary, 
            ds, 0, 0, 0, 0, NULL);
            
          if(ht != NULL) {
            printf("OK\n6. Waiting for thread to exit.\n");
            li.QuadPart = INFINITE;
            nts = syscall->NtWaitForSingleObject(ht, FALSE, &li);
            printf("7. Close thread handle.\n");
            syscall->NtClose(ht);
          } else printf("FAILED! %08X\n", nts);
        }
        printf("7. Free remote memory.\n");
        syscall->NtFreeVirtualMemory(hp, ds, 0, MEM_RELEASE);
      } else printf("FAILED! %08X\n", nts);
      printf("8. Closing process handle.\n");
      syscall->NtClose(hp);
    } else printf("FAILED! %08X\n", nts);
}

int main(int argc, char *argv[]) {
    syscall_t sc;
    DWORD     pid;
    
    if(argc != 3) {
      printf("usage: inject_dll <process name | id> <path of DLL>\n");
      return 0;
    }
    
    pid = strtoul(argv[1], NULL, 10);
    if(pid == 0) {
      pid = name2pid(argv[1]);
      if(pid == 0) {
        printf("unable to find process : %s\n", argv[1]);
        return -1;
      }
    }
    
    // resolve address of system calls
    sc.NtOpenProcess           = (NtOpenProcess_t)GetSyscallStub("NtOpenProcess");
    sc.NtAllocateVirtualMemory = (NtAllocateVirtualMemory_t)GetSyscallStub("NtAllocateVirtualMemory");
    sc.NtWriteVirtualMemory    = (NtWriteVirtualMemory_t)GetSyscallStub("NtWriteVirtualMemory");
    sc.NtCreateThreadEx        = (NtCreateThreadEx_t)GetSyscallStub("NtCreateThreadEx");
    sc.NtWaitForSingleObject   = (NtWaitForSingleObject_t)GetSyscallStub("NtWaitForSingleObject");
    sc.NtFreeVirtualMemory     = (NtFreeVirtualMemory_t)GetSyscallStub("NtFreeVirtualMemory");
    sc.NtClose                 = (NtClose_t)GetSyscallStub("NtClose");
    
    if(sc.NtOpenProcess == NULL ||
       sc.NtAllocateVirtualMemory == NULL ||
       sc.NtWriteVirtualMemory == NULL ||
       sc.NtCreateThreadEx == NULL ||
       sc.NtWaitForSingleObject == NULL ||
       sc.NtFreeVirtualMemory == NULL ||
       sc.NtClose == NULL) {
      
      printf("unable to resolve address of some system calls.\n");
      printf("NtOpenProcess           : %p\n", sc.NtOpenProcess);
      printf("NtAllocateVirtualMemory : %p\n", sc.NtAllocateVirtualMemory);
      printf("NtWriteVirtualMemory    : %p\n", sc.NtWriteVirtualMemory);
      printf("NtCreateThreadEx        : %p\n", sc.NtCreateThreadEx);
      printf("NtWaitForSingleObject   : %p\n", sc.NtWaitForSingleObject);
      printf("NtFreeVirtualMemory     : %p\n", sc.NtFreeVirtualMemory);
      printf("NtClose                 : %p\n", sc.NtClose);
    } else {
      printf("Injecting %s into %s...\n", argv[2], argv[1]);
      inject_dll(&sc, pid, argv[2]);
    }
    
    return 0;
}
