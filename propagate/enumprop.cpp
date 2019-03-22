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
#include <tlhelp32.h>
#include <psapi.h>

#pragma comment(lib, "user32.lib")

#include <iostream>
#include <vector>
#include <algorithm>

typedef struct _win_props_t {
  DWORD  dwPid;
  WCHAR  ImageName[MAX_PATH];
  HANDLE hProperty;
  HWND   hParentWnd;
  HWND   hChildWnd;
  WCHAR  ParentClassName[MAX_PATH];
  WCHAR  ChildClassName[MAX_PATH];
} WINPROPS, *PWINPROPS;
  
std::vector<WINPROPS> windows;
int maxName=16, maxClass=16;
bool bAll=true;

// we want to ignore duplicates
BOOL IsEntry(PWINPROPS e) {
    BOOL bFound = FALSE;
    
    for(int i=0;i<windows.size(); i++) {
      // same process id?
      if(e->dwPid == windows.at(i).dwPid) {
        // same property?
        if(e->hProperty == windows.at(i).hProperty) {
          bFound = TRUE;
          break;
        }
      }
    }
    return bFound;
}

BOOL GetProcessImageName(DWORD dwPid, LPWSTR ImageName, DWORD dwSize) {
    HANDLE         hSnap;
    PROCESSENTRY32 pe32;
    BOOL           bFound=FALSE;
    
    // create snapshot of system
    hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if(hSnap == INVALID_HANDLE_VALUE) return 0;
    
    pe32.dwSize = sizeof(PROCESSENTRY32);

    // get first process
    if(Process32First(hSnap, &pe32)){
      do {
        if(dwPid == pe32.th32ProcessID) {
          lstrcpyn(ImageName, pe32.szExeFile, dwSize);
          bFound = TRUE;
          break;
        }
      } while(Process32Next(hSnap, &pe32));
    }
    CloseHandle(hSnap);
    return bFound;
}

// callback for property list
BOOL CALLBACK PropEnumProc(HWND hwnd, 
  LPCTSTR lpszString, HANDLE hData) 
{
    WINPROPS wp;
    HANDLE   hp;
    
    hp = GetProp(hwnd, L"UxSubclassInfo");
    if(hp==NULL) hp = GetProp(hwnd, L"CC32SubclassInfo");
    
    if(hp != NULL) {
      ZeroMemory(&wp, sizeof(wp));
      
      GetWindowThreadProcessId(hwnd, &wp.dwPid);
      
      wp.hProperty  = hp;
      wp.hChildWnd  = hwnd;
      wp.hParentWnd = GetParent(hwnd);
      
      GetClassName(wp.hParentWnd, wp.ParentClassName, MAX_PATH);
      GetClassName(hwnd, wp.ChildClassName, MAX_PATH); 
      GetProcessImageName(wp.dwPid, wp.ImageName, MAX_PATH);
      
      maxName  = max(maxName,  lstrlen(wp.ImageName));
      maxClass = max(maxClass, lstrlen(wp.ParentClassName));
      
      // if not already saved
      if(!IsEntry(&wp)) {
        windows.push_back(wp);
      }
    }
    return TRUE;
}

// callback for child windows
BOOL CALLBACK EnumChildProc(HWND hwnd, LPARAM lParam) {
    EnumProps(hwnd, PropEnumProc);
    
    return TRUE;
}

// callback for parent windows
BOOL CALLBACK EnumWindowsProc(HWND hwnd, LPARAM lParam) {
    EnumChildWindows(hwnd, EnumChildProc, 0);
    EnumProps(hwnd, PropEnumProc);
    
    return TRUE;
}

bool sortEntries(const WINPROPS &a, const WINPROPS &b) {
    return lstrcmp(a.ParentClassName, b.ParentClassName)<0;
}

int GetPropList(void) {
  
    windows.clear();
    
    EnumWindows(EnumWindowsProc, 0);
    
    std::sort(windows.begin(), windows.end(), sortEntries);
    
    return windows.size();
}

int wmain(int argc, wchar_t *argv[]){
    GetPropList();

    wprintf(L"\n\n%-5s\t%-*s\t%-*s\t%-*s\t%-16s\n", 
      L"PID", 
      maxName,  L"Image Name", 
      maxClass, L"Parent Class", 
      maxClass, L"Child Class",
      L"Subclass Header");

    wprintf(L"%s\t%s\t%s\t%s\t%s\n", 
      std::wstring(5,        L'-').c_str(), 
      std::wstring(maxName,  L'-').c_str(), 
      std::wstring(maxClass, L'-').c_str(),
      std::wstring(maxClass, L'-').c_str(),
      std::wstring(16,       L'-').c_str());
      
    for(int i=0;i<windows.size(); i++) {
      if(!bAll && lstrcmpi(L"explorer.exe", 
        windows.at(i).ImageName)!=0) continue;
      
      wprintf(L"%-5i\t%-*s\t%-*s\t%-*s\t%p\n", 
        windows.at(i).dwPid,
        maxName,
        windows.at(i).ImageName,
        maxClass,
        windows.at(i).ParentClassName,
        maxClass,
        windows.at(i).ChildClassName,
        (void*)windows.at(i).hProperty);
    }
    wprintf(L"\nFound %lld subclassed windows\n", windows.size());
    return 0;
}