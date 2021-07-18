
#ifndef LDE_H
#define LDE_H

#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <dbgeng.h>

#pragma comment(lib, "dbgeng.lib")
#pragma comment(lib, "dbghelp.lib")
#pragma comment(lib, "shell32.lib")

#define LDE_OPCODE_JO   0x70 // JO
#define LDE_OPCODE_JNO  0x71 // JNO
#define LDE_OPCODE_JB   0x72 // JB
#define LDE_OPCODE_JAE  0x73 // JAE
#define LDE_OPCODE_JE   0x74 // JE
#define LDE_OPCODE_JNE  0x75 // JNE
#define LDE_OPCODE_JBE  0x76 // JBE
#define LDE_OPCODE_JA   0x77 // JA
#define LDE_OPCODE_JS   0x78 // JS
#define LDE_OPCODE_JNS  0x79 // JNS
#define LDE_OPCODE_JP   0x7A // JP
#define LDE_OPCODE_JPO  0x7B // JPO
#define LDE_OPCODE_JNGE 0x7C // JNGE
#define LDE_OPCODE_JNL  0x7D // JNL
#define LDE_OPCODE_JNG  0x7E // JNG
#define LDE_OPCODE_JNLE 0x7F // JNLE
       
#define LDE_MAX_STR 260

typedef struct _lde_insn_t {
    ULONG64 size, addr, ofs, target;
    DWORD   type;
    BYTE    code[16];
    CHAR    buf[LDE_MAX_STR];
} lde_insn_t;

class LDE {
  private:
    HANDLE               file, map;
    LPBYTE               mem;
    HRESULT              hr;
    IDebugClient         *clnt;
    IDebugControl2       *ctrl;
    
    PIMAGE_DOS_HEADER DosHdr(void);
    PIMAGE_NT_HEADERS NtHdr(void);
    PIMAGE_FILE_HEADER FileHdr(void);
    BOOL is32(void);
    BOOL is64(void);
    LPVOID OptHdr(void);
    PIMAGE_SECTION_HEADER SecHdr(void);
    DWORD DirSize(void);
    DWORD SecSize(void);
    PIMAGE_DATA_DIRECTORY Dirs(void);
    ULONGLONG ImgBase(void);
    ULONG64 rva2ofs(DWORD rva);
    
  public:
    LDE();
    ~LDE();
    
    bool Disassemble(lde_insn_t*);
    FARPROC GetProcAddress(LPCSTR);
    bool DisassembleSyscall(LPCSTR);
    LPVOID GetSyscallStub(LPCSTR);
};

#endif
