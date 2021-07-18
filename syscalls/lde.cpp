

#include "lde.h"

LDE::LDE() {
    CHAR path[MAX_PATH];
    
    ctrl = NULL;
    clnt = NULL;
    // create a debugging client
    hr = DebugCreate(__uuidof(IDebugClient), (void**)&clnt);
    if(hr == S_OK) {
      printf("Querying interface...\n");
      // get the control interface
      hr = clnt->QueryInterface(__uuidof(IDebugControl2), (void**)&ctrl);
      if(hr == S_OK) {
        printf("Attaching to %ld...\n", GetProcessId(GetCurrentProcess()));
        // attach to existing process
        hr = clnt->AttachProcess(NULL, GetProcessId(GetCurrentProcess()), DEBUG_ATTACH_NONINVASIVE | DEBUG_ATTACH_NONINVASIVE_NO_SUSPEND);
        if(hr == S_OK) {
          printf("Waiting for events...\n");
          hr = ctrl->WaitForEvent(DEBUG_WAIT_DEFAULT, INFINITE);
        } else printf("ERROR: %08lX\n", hr);
      }
    }
    ExpandEnvironmentStrings("%SystemRoot%\\system32\\NTDLL.dll", path, MAX_PATH);
    // open file
    file = CreateFile(path, 
      GENERIC_READ, FILE_SHARE_READ, NULL, 
      OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
      
    if(file == INVALID_HANDLE_VALUE) return;
    
    // create mapping
    map = CreateFileMapping(file, NULL, PAGE_READONLY, 0, 0, NULL);
    if(map == NULL) return;
    
    // create view
    mem = (LPBYTE)MapViewOfFile(map, FILE_MAP_READ, 0, 0, NULL);
}

LDE::~LDE() {
    if(mem != NULL) UnmapViewOfFile(mem);
    if(map != NULL) CloseHandle(map);
    if(file != NULL) CloseHandle(file);
    
    if(ctrl != NULL) {
      ctrl->Release();
      ctrl = NULL;
    }
    
    // release client
    if(clnt != NULL) {
      clnt->DetachProcesses();
      clnt->Release();
      clnt = NULL;
    }
}

// return pointer to DOS header
PIMAGE_DOS_HEADER LDE::DosHdr(void) {
    return (PIMAGE_DOS_HEADER)mem;
}

// return pointer to NT header
PIMAGE_NT_HEADERS LDE::NtHdr(void) {
  DWORD v = DosHdr()->e_lfanew;
  
  if (v > 512) {
    //printf("%s is wrong\n", file);
    return NULL;
  }
  return (PIMAGE_NT_HEADERS) (mem + DosHdr()->e_lfanew);
}

// return pointer to File header
PIMAGE_FILE_HEADER LDE::FileHdr(void) {
  PIMAGE_NT_HEADERS nt = NtHdr();
  if (nt == NULL) return NULL;
  
  return &NtHdr()->FileHeader;
}
// determines CPU architecture of binary
BOOL LDE::is32(void) {
    PIMAGE_FILE_HEADER hdr = FileHdr();
    if (hdr == NULL) return FALSE;
    
    return FileHdr()->Machine==IMAGE_FILE_MACHINE_I386;
}

// determines CPU architecture of binary
BOOL LDE::is64(void) {
    PIMAGE_FILE_HEADER hdr = FileHdr();
    if (hdr == NULL) return FALSE;
    
    return FileHdr()->Machine == IMAGE_FILE_MACHINE_AMD64;
}

// return pointer to Optional header
LPVOID LDE::OptHdr(void) {
    return (LPVOID)&NtHdr()->OptionalHeader;
}

// return pointer to first section header
PIMAGE_SECTION_HEADER LDE::SecHdr(void) {
    PIMAGE_NT_HEADERS nt = NtHdr();
    if (nt == NULL) return NULL;
    
    return (PIMAGE_SECTION_HEADER)((LPBYTE)&nt->OptionalHeader + 
    nt->FileHeader.SizeOfOptionalHeader);
}

DWORD LDE::DirSize(void) {
    if (is32()) {
      return ((PIMAGE_OPTIONAL_HEADER32)OptHdr())->NumberOfRvaAndSizes;
    } else if (is64()) {
      return ((PIMAGE_OPTIONAL_HEADER64)OptHdr())->NumberOfRvaAndSizes;
    }
    return 0;
}

DWORD LDE::SecSize(void) {
    return NtHdr()->FileHeader.NumberOfSections;
}

PIMAGE_DATA_DIRECTORY LDE::Dirs(void) {
    if (DirSize() == 0) return NULL;
    
    if (is32()) {
      return ((PIMAGE_OPTIONAL_HEADER32)OptHdr())->DataDirectory;
    } else if (is64()) {
      return ((PIMAGE_OPTIONAL_HEADER64)OptHdr())->DataDirectory;
    }
    return NULL;
}

ULONGLONG LDE::ImgBase(void) {
    if (is32()) {
      return ((PIMAGE_OPTIONAL_HEADER32)OptHdr())->ImageBase;
    } else if (is64()) {
      return ((PIMAGE_OPTIONAL_HEADER64)OptHdr())->ImageBase;
    }
    return 0;
}

ULONG64 LDE::rva2ofs(DWORD rva) {
    PIMAGE_SECTION_HEADER	sec;
    int				            i;
    
    if (rva == 0) return -1;
    sec = SecHdr();
    
    if (sec==0) return -1;
    
    for (i = SecSize() - 1; i >= 0; i--) {
      if (sec[i].VirtualAddress <= rva &&
        rva <= (DWORD)sec[i].VirtualAddress + sec[i].SizeOfRawData)
      {
        return sec[i].PointerToRawData + rva - sec[i].VirtualAddress;
      }
    }
    return -1;
}

FARPROC LDE::GetProcAddress(LPCSTR lpProcName) {
    PIMAGE_DATA_DIRECTORY   dir;
    PIMAGE_EXPORT_DIRECTORY exp;
    DWORD                   rva, ofs, cnt;
    PCHAR                   str;
    PDWORD                  adr, sym;
    PWORD                   ord;
    
    if(mem == NULL || lpProcName == NULL) return NULL;
    
    // get pointer to directory
    dir = Dirs();
    
    // no exports? exit
    rva = dir[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if(rva == 0) return NULL;
    
    ofs = rva2ofs(rva);
    if(ofs == -1) return NULL;
    
    // no exported symbols? exit
    exp = (PIMAGE_EXPORT_DIRECTORY)(ofs + mem);
    cnt = exp->NumberOfNames;
    if(cnt == 0) return NULL;
    
    // read the array containing address of api names
    ofs = rva2ofs(exp->AddressOfNames);        
    if(ofs == -1) return NULL;
    sym = (PDWORD)(ofs + mem);

    // read the array containing address of api
    ofs = rva2ofs(exp->AddressOfFunctions);        
    if(ofs == -1) return NULL;
    adr = (PDWORD)(ofs + mem);
    
    // read the array containing list of ordinals
    ofs = rva2ofs(exp->AddressOfNameOrdinals);
    if(ofs == -1) return NULL;
    ord = (PWORD)(ofs + mem);
    
    // scan symbol array for api string
    do {
      str = (PCHAR)(rva2ofs(sym[cnt - 1]) + mem);
      // found it?
      if(lstrcmp(str, lpProcName) == 0) {
        // return the address
        return (FARPROC)(rva2ofs(adr[ord[cnt - 1]]) + mem);
      }
    } while (--cnt);
    return NULL;
}

LPVOID LDE::GetSyscallStub(LPCSTR lpSyscallName) {
    ULONG64                       ofs, start=0, end=0, addr;
    PIMAGE_DOS_HEADER             dos;
    PIMAGE_NT_HEADERS             nt;
    PIMAGE_DATA_DIRECTORY         dir;
    PIMAGE_RUNTIME_FUNCTION_ENTRY rf;
    DWORD                         i, rva;
    SIZE_T                        len;
    LPVOID                        cs = NULL;
    
    // resolve address of function in NTDLL
    addr = (ULONG64)GetProcAddress(lpSyscallName);
    if(addr == NULL) return NULL;
    
    // get pointer to image directories
    dir = Dirs();
    
    // no exception directory? exit
    rva = dir[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress;
    if(rva == 0) return NULL;
    
    ofs = rva2ofs(rva);
    if(ofs == -1) return NULL;
    
    rf = (PIMAGE_RUNTIME_FUNCTION_ENTRY)(ofs + mem);

    // for each runtime function (there might be a better way??)
    for(i=0; rf[i].BeginAddress != 0; i++) {
      // is it our system call?
      start = rva2ofs(rf[i].BeginAddress) + (ULONG64)mem;
      if(start == addr) {
        // save the end and calculate length
        end = rva2ofs(rf[i].EndAddress) + (ULONG64)mem;
        len = (SIZE_T) (end - start);
        
        // allocate RWX memory
        cs = VirtualAlloc(NULL, len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if(cs != NULL) {
          // copy stub to memory
          CopyMemory(cs, (const void*)start, len);
        }
        break;
      }
    }
    // return pointer to code stub
    return cs;
}

bool LDE::DisassembleSyscall(LPCSTR lpSyscallName) {
    ULONG64                       ofs, start=0, end=0, addr;
    PIMAGE_DOS_HEADER             dos;
    PIMAGE_NT_HEADERS             nt;
    PIMAGE_DATA_DIRECTORY         dir;
    PIMAGE_RUNTIME_FUNCTION_ENTRY rf;
    DWORD                         i, rva;
    CHAR                          buf[LDE_MAX_STR];
    HRESULT                       hr;
    ULONG                         len;
    
    // resolve address of function in NTDLL
    addr = (ULONG64)GetProcAddress(lpSyscallName);
    if(addr == NULL) return false;
    
    /** get pointer to image directories
    dir = Dirs();
    
    // no exception directory? exit
    rva = dir[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress;
    if(rva == 0) return false;
    
    ofs = rva2ofs(rva);
    if(ofs == -1) return false;
    
    rf = (PIMAGE_RUNTIME_FUNCTION_ENTRY)(ofs + mem);

    // for each runtime function (there might be a better way??)
    for(i=0; rf[i].BeginAddress != 0; i++) {
      // is it our system call?
      start = rva2ofs(rf[i].BeginAddress) + (ULONG64)mem;
      if(start == addr) {
        // save end and exit search
        end = rva2ofs(rf[i].EndAddress) + (ULONG64)mem;
        break;
      }
    }*/
    
    printf("Disassembling %p\n", (PVOID)addr);
    start = addr;

    for(;;) {
      hr = ctrl->Disassemble(
            start, 
            0, 
            buf, 
            LDE_MAX_STR, 
            &len, 
            &start
            );
        
      if(hr != S_OK) {
        printf("Done %08lX\n", hr);
        break;
      }
      printf("%s", buf);
    }
    return false;
}

bool LDE::Disassemble(lde_insn_t *inst) {
    ULONG i, j, dislen;
    int   val;
    int   x, ofs, instlen;
    
    // Disassemble instruction at current address
    hr = ctrl->Disassemble(
      inst->addr, 0, inst->buf, LDE_MAX_STR,
      &dislen, &inst->ofs);
    
    // Error? return
    if(hr != S_OK) return false;
    
    // Calculate the length of opcode
    inst->size = (inst->ofs - inst->addr);
    
    // Skip the address
    for(i=0; inst->buf[i] != ' ' && i < dislen; i++);
    
    // Find code bytes
    for(;inst->buf[i] == ' '; i++);
    
    // Convert bytes to binary
    for(j=0; inst->buf[i] != ' ' && i < dislen; i += 2, j++) {
      sscanf (&inst->buf[i], "%2x", &val);
      inst->code[j] = (BYTE)val;
    }
    
    // Inspect opcode
    x = inst->code[0];
    inst->target = 0;

    // is it a branch?
    if(((x & 0xF0) == 0x70) ||
       ((x & 0xF0) == 0xE0 && x != 0xE8) ||
       (x == 0x0F) && 
       (inst->code[1] >= 0x81) && 
       (inst->code[1] <= 0x8F)) 
    {  
      // short?
      if(inst->size == 2) {
        ofs = inst->code[1];
        if(ofs & 0x80) {
          inst->target = inst->addr - (0xFF - ofs - 1);
        } else {
          inst->target = inst->addr + inst->size + ofs;
        }
      } else {
        instlen = inst->size - 2;
        if(x == 0xE9) instlen++;
        ofs = 0;
        // long?
        for(i=0; i<instlen; i++) {
          ofs <<= 8;
          ofs |= inst->code[inst->size - i - 1];
        }
        if(ofs & 0x80000000) {          
          inst->target = inst->addr - (0xFFFFFFFF - ofs - 4);
        } else {
          inst->target = inst->addr + inst->size + ofs;
        }
      }
    }
    return true;
}
