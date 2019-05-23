

#include "../ntlib/util.h"

VOID ScanProcess(DWORD pid) {
    HANDLE                   hProcess;
    SYSTEM_INFO              si;
    MEMORY_BASIC_INFORMATION mbi;
    LPBYTE                   addr;     // current address
    SIZE_T                   res;
    
    hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    
    if (hProcess != NULL) {
      GetSystemInfo(&si);
      
      for (addr=0; addr < (LPBYTE)si.lpMaximumApplicationAddress;) {
        ZeroMemory(&mbi, sizeof(mbi));
        res = VirtualQueryEx(hProcess, addr, &mbi, sizeof(mbi));

        if (mbi.Protect == PAGE_EXECUTE_READWRITE) 
        {
          wprintf(L"%p : %zi\n", mbi.BaseAddress, mbi.RegionSize);
        }
        addr = (PBYTE)mbi.BaseAddress + mbi.RegionSize;
      }
      CloseHandle(hProcess);
    }
}

VOID ScanSystem(DWORD pid) {
    HANDLE         hSnap;
    PROCESSENTRY32 pe32;
    BOOL           bFound=FALSE;
    
    hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if(hSnap == INVALID_HANDLE_VALUE) return;
    
    pe32.dwSize = sizeof(PROCESSENTRY32);

    if(Process32First(hSnap, &pe32)){
      do {
        if(pid != 0 && pe32.th32ProcessID != pid) continue;
        printf("Checking %ws\n\n", pe32.szExeFile);
        ScanProcess(pe32.th32ProcessID);
      } while(Process32Next(hSnap, &pe32));
    }
    CloseHandle(hSnap);
}

int main(void) {
    PWCHAR *argv;
    int    argc;
    DWORD  pid = 0;
    
    argv = CommandLineToArgvW(GetCommandLine(), &argc);
    
    SetPrivilege(SE_DEBUG_NAME, TRUE);

    if(argc == 2) {
      pid = name2pid(argv[1]);
      if(pid == 0) pid = _wtoi(argv[1]);
      if(pid == 0) {
        printf("unable to resolve pid for \"%ws\"\n", argv[1]);
        return 0;
      }
    }
    ScanSystem(pid);
    return 0;
}
