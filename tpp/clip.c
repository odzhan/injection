
#define UNICODE
#include <windows.h>
#include <stdio.h>
#pragma comment(lib, "user32.lib")

int main(int argc, char *argv[]) {
    HWND           hw;

    if(argc != 2) {
      printf("usage: clipbrd <window handle>\n");
      return 0;
    }
    
    hw = (HWND)strtoul(argv[1], NULL, 16);

    SendMessage(hw, WM_DESTROYCLIPBOARD, 0, 0);
    
    printf("ClipboardDataObjectInterface     : %p\n", GetProp(hw, L"ClipboardDataObjectInterface"));
    printf("ClipboardRootDataObjectInterface : %p\n", GetProp(hw, L"ClipboardRootDataObjectInterface"));
    printf("ClipboardDataObjectInterfaceMTA  : %p\n", GetProp(hw, L"ClipboardDataObjectInterfaceMTA" ));
    printf("OLEClipPackgeOwner               : %p\n", GetProp(hw, L"OLEClipPackgeOwner"));
    printf("OleClipProcessOwner              : %p\n", GetProp(hw, L"OleClipProcessOwner"));
    return 0;
}
