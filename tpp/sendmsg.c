
#define UNICODE
#include <windows.h>
#include <commctrl.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <stdio.h>

#pragma comment(lib, "user32.lib")

typedef struct {
    unsigned int code;
    wchar_t* text;
} XMSGITEM;

XMSGITEM xmsglist[] =
{
    { 0, L"WM_NULL"},
    { 1, L"WM_CREATE" },
   // { 2, L"WM_DESTROY" },
    { 3, L"WM_MOVE" },
    { 5, L"WM_SIZE" },
    { 6, L"WM_ACTIVATE" },
    { 7, L"WM_SETFOCUS" },
    { 8, L"WM_KILLFOCUS" },
    { 10, L"WM_ENABLE" },
    { 11, L"WM_SETREDRAW" },
    { 12, L"WM_SETTEXT" },
    { 13, L"WM_GETTEXT" },
    { 14, L"WM_GETTEXTLENGTH" },
    { 15, L"WM_PAINT" },
    //{ 16, L"WM_CLOSE" },
    { 17, L"WM_QUERYENDSESSION" },
    //{ 18, L"WM_QUIT" },
    { 19, L"WM_QUERYOPEN" },
    { 20, L"WM_ERASEBKGND" },
    { 21, L"WM_SYSCOLORCHANGE" },
    { 22, L"WM_ENDSESSION" },
    { 24, L"WM_SHOWWINDOW" },
    { 25, L"WM_CTLCOLOR" },
    { 26, L"WM_WININICHANGE" },
    { 27, L"WM_DEVMODECHANGE" },
    { 28, L"WM_ACTIVATEAPP" },
    { 29, L"WM_FONTCHANGE" },
    { 30, L"WM_TIMECHANGE" },
    { 31, L"WM_CANCELMODE" },
    { 32, L"WM_SETCURSOR" },
    { 33, L"WM_MOUSEACTIVATE" },
    { 34, L"WM_CHILDACTIVATE" },
    { 35, L"WM_QUEUESYNC" },
    { 36, L"WM_GETMINMAXINFO" },
    { 38, L"WM_PAINTICON" },
    { 39, L"WM_ICONERASEBKGND" },
    { 40, L"WM_NEXTDLGCTL" },
    { 42, L"WM_SPOOLERSTATUS" },
    { 43, L"WM_DRAWITEM" },
    { 44, L"WM_MEASUREITEM" },
    { 45, L"WM_DELETEITEM" },
    { 46, L"WM_VKEYTOITEM" },
    { 47, L"WM_CHARTOITEM" },
    { 48, L"WM_SETFONT" },
    { 49, L"WM_GETFONT" },
    { 50, L"WM_SETHOTKEY" },
    { 51, L"WM_GETHOTKEY" },
    { 55, L"WM_QUERYDRAGICON" },
    { 57, L"WM_COMPAREITEM" },
    { 61, L"WM_GETOBJECT" },
    { 65, L"WM_COMPACTING" },
    { 68, L"WM_COMMNOTIFY" },
    { 70, L"WM_WINDOWPOSCHANGING" },
    { 71, L"WM_WINDOWPOSCHANGED" },
    { 72, L"WM_POWER" },
    { 73, L"WM_COPYGLOBALDATA" },
    { 74, L"WM_COPYDATA" },
    { 75, L"WM_CANCELJOURNAL" },
    { 78, L"WM_NOTIFY" },
    { 80, L"WM_INPUTLANGCHANGEREQUEST" },
    { 81, L"WM_INPUTLANGCHANGE" },
    { 82, L"WM_TCARD" },
    { 83, L"WM_HELP" },
    { 84, L"WM_USERCHANGED" },
    { 85, L"WM_NOTIFYFORMAT" },
    { 123, L"WM_CONTEXTMENU" },
    { 124, L"WM_STYLECHANGING" },
    { 125, L"WM_STYLECHANGED" },
    { 126, L"WM_DISPLAYCHANGE" },
    { 127, L"WM_GETICON" },
    { 128, L"WM_SETICON" },
    { 129, L"WM_NCCREATE" },
    { 130, L"WM_NCDESTROY" },
    { 131, L"WM_NCCALCSIZE" },
    { 132, L"WM_NCHITTEST" },
    { 133, L"WM_NCPAINT" },
    { 134, L"WM_NCACTIVATE" },
    { 135, L"WM_GETDLGCODE" },
    { 136, L"WM_SYNCPAINT" },
    { 160, L"WM_NCMOUSEMOVE" },
    { 161, L"WM_NCLBUTTONDOWN" },
    { 162, L"WM_NCLBUTTONUP" },
    { 163, L"WM_NCLBUTTONDBLCLK" },
    { 164, L"WM_NCRBUTTONDOWN" },
    { 165, L"WM_NCRBUTTONUP" },
    { 166, L"WM_NCRBUTTONDBLCLK" },
    { 167, L"WM_NCMBUTTONDOWN" },
    { 168, L"WM_NCMBUTTONUP" },
    { 169, L"WM_NCMBUTTONDBLCLK" },
    { 171, L"WM_NCXBUTTONDOWN" },
    { 172, L"WM_NCXBUTTONUP" },
    { 173, L"WM_NCXBUTTONDBLCLK" },
    { 176, L"EM_GETSEL" },
    { 177, L"EM_SETSEL" },
    { 178, L"EM_GETRECT" },
    { 179, L"EM_SETRECT" },
    { 180, L"EM_SETRECTNP" },
    { 181, L"EM_SCROLL" },
    { 182, L"EM_LINESCROLL" },
    { 183, L"EM_SCROLLCARET" },
    { 185, L"EM_GETMODIFY" },
    { 187, L"EM_SETMODIFY" },
   // { 188, L"EM_GETLINECOUNT" },
   // { 189, L"EM_LINEINDEX" },
    { 190, L"EM_SETHANDLE" },
    { 191, L"EM_GETHANDLE" },
    { 192, L"EM_GETTHUMB" },
    { 193, L"EM_LINELENGTH" },
    { 194, L"EM_REPLACESEL" },
    { 195, L"EM_SETFONT" },
    { 196, L"EM_GETLINE" },
    { 197, L"EM_LIMITTEXT" },
    { 197, L"EM_SETLIMITTEXT" },
    { 198, L"EM_CANUNDO" },
    { 199, L"EM_UNDO" },
    { 200, L"EM_FMTLINES" },
    { 201, L"EM_LINEFROMCHAR" },
    { 202, L"EM_SETWORDBREAK" },
    { 203, L"EM_SETTABSTOPS" },
    { 204, L"EM_SETPASSWORDCHAR" },
    { 205, L"EM_EMPTYUNDOBUFFER" },
    { 206, L"EM_GETFIRSTVISIBLELINE" },
    { 207, L"EM_SETREADONLY" },
    { 209, L"EM_SETWORDBREAKPROC" },
    { 209, L"EM_GETWORDBREAKPROC" },
    { 210, L"EM_GETPASSWORDCHAR" },
    { 211, L"EM_SETMARGINS" },
    { 212, L"EM_GETMARGINS" },
    { 213, L"EM_GETLIMITTEXT" },
    { 214, L"EM_POSFROMCHAR" },
    { 215, L"EM_CHARFROMPOS" },
    { 216, L"EM_SETIMESTATUS" },
    { 217, L"EM_GETIMESTATUS" },
    { 224, L"SBM_SETPOS" },
    { 225, L"SBM_GETPOS" },
    { 226, L"SBM_SETRANGE" },
    { 227, L"SBM_GETRANGE" },
    { 228, L"SBM_ENABLE_ARROWS" },
    { 230, L"SBM_SETRANGEREDRAW" },
    { 233, L"SBM_SETSCROLLINFO" },
    { 234, L"SBM_GETSCROLLINFO" },
    { 235, L"SBM_GETSCROLLBARINFO" },
    { 240, L"BM_GETCHECK" },
    { 241, L"BM_SETCHECK" },
    { 242, L"BM_GETSTATE" },
    { 243, L"BM_SETSTATE" },
    { 244, L"BM_SETSTYLE" },
    { 245, L"BM_CLICK" },
    { 246, L"BM_GETIMAGE" },
    { 247, L"BM_SETIMAGE" },
    { 248, L"BM_SETDONTCLICK" },
    { 255, L"WM_INPUT" },
    { 256, L"WM_KEYDOWN" },
    { 256, L"WM_KEYFIRST" },
    { 257, L"WM_KEYUP" },
    { 258, L"WM_CHAR" },
    { 259, L"WM_DEADCHAR" },
    { 260, L"WM_SYSKEYDOWN" },
    { 261, L"WM_SYSKEYUP" },
    { 262, L"WM_SYSCHAR" },
    { 263, L"WM_SYSDEADCHAR" },
    { 264, L"WM_KEYLAST" },
    { 265, L"WM_UNICHAR" },
    { 265, L"WM_WNT_CONVERTREQUESTEX" },
    { 266, L"WM_CONVERTREQUEST" },
    { 267, L"WM_CONVERTRESULT" },
    { 268, L"WM_INTERIM" },
    { 269, L"WM_IME_STARTCOMPOSITION" },
    { 270, L"WM_IME_ENDCOMPOSITION" },
    { 271, L"WM_IME_COMPOSITION" },
    { 271, L"WM_IME_KEYLAST" },
    { 272, L"WM_INITDIALOG" },
    { 273, L"WM_COMMAND" },
    { 274, L"WM_SYSCOMMAND" },
    { 275, L"WM_TIMER" },
    { 276, L"WM_HSCROLL" },
    { 277, L"WM_VSCROLL" },
    { 278, L"WM_INITMENU" },
    { 279, L"WM_INITMENUPOPUP" },
    { 280, L"WM_SYSTIMER" },
    { 287, L"WM_MENUSELECT" },
    { 288, L"WM_MENUCHAR" },
    { 289, L"WM_ENTERIDLE" },
    { 290, L"WM_MENURBUTTONUP" },
    { 291, L"WM_MENUDRAG" },
    { 292, L"WM_MENUGETOBJECT" },
    { 293, L"WM_UNINITMENUPOPUP" },
    { 294, L"WM_MENUCOMMAND" },
    { 295, L"WM_CHANGEUISTATE" },
    { 296, L"WM_UPDATEUISTATE" },
    { 297, L"WM_QUERYUISTATE" },
    { 306, L"WM_CTLCOLORMSGBOX" },
    { 307, L"WM_CTLCOLOREDIT" },
    { 308, L"WM_CTLCOLORLISTBOX" },
    { 309, L"WM_CTLCOLORBTN" },
    { 310, L"WM_CTLCOLORDLG" },
    { 311, L"WM_CTLCOLORSCROLLBAR" },
    { 312, L"WM_CTLCOLORSTATIC" },
    { 512, L"WM_MOUSEFIRST" },
    { 512, L"WM_MOUSEMOVE" },
    { 513, L"WM_LBUTTONDOWN" },
    { 514, L"WM_LBUTTONUP" },
    { 515, L"WM_LBUTTONDBLCLK" },
    { 516, L"WM_RBUTTONDOWN" },
    { 517, L"WM_RBUTTONUP" },
    { 518, L"WM_RBUTTONDBLCLK" },
    { 519, L"WM_MBUTTONDOWN" },
    { 520, L"WM_MBUTTONUP" },
    { 521, L"WM_MBUTTONDBLCLK" },
    { 521, L"WM_MOUSELAST" },
    { 522, L"WM_MOUSEWHEEL" },
    { 523, L"WM_XBUTTONDOWN" },
    { 524, L"WM_XBUTTONUP" },
    { 525, L"WM_XBUTTONDBLCLK" },
    { 528, L"WM_PARENTNOTIFY" },
    { 529, L"WM_ENTERMENULOOP" },
    { 530, L"WM_EXITMENULOOP" },
    { 531, L"WM_NEXTMENU" },
    { 532, L"WM_SIZING" },
    { 533, L"WM_CAPTURECHANGED" },
    { 534, L"WM_MOVING" },
    { 536, L"WM_POWERBROADCAST" },
    { 537, L"WM_DEVICECHANGE" },
    { 544, L"WM_MDICREATE" },
    { 545, L"WM_MDIDESTROY" },
    { 546, L"WM_MDIACTIVATE" },
    { 547, L"WM_MDIRESTORE" },
    { 548, L"WM_MDINEXT" },
    { 549, L"WM_MDIMAXIMIZE" },
    { 550, L"WM_MDITILE" },
    { 551, L"WM_MDICASCADE" },
    { 552, L"WM_MDIICONARRANGE" },
    { 553, L"WM_MDIGETACTIVE" },
    { 560, L"WM_MDISETMENU" },
    { 561, L"WM_ENTERSIZEMOVE" },
    { 562, L"WM_EXITSIZEMOVE" },
    { 563, L"WM_DROPFILES" },
    { 564, L"WM_MDIREFRESHMENU" },
    { 640, L"WM_IME_REPORT" },
    { 641, L"WM_IME_SETCONTEXT" },
    { 642, L"WM_IME_NOTIFY" },
    { 643, L"WM_IME_CONTROL" },
    { 644, L"WM_IME_COMPOSITIONFULL" },
    { 645, L"WM_IME_SELECT" },
    { 646, L"WM_IME_CHAR" },
    { 648, L"WM_IME_REQUEST" },
    { 656, L"WM_IMEKEYDOWN" },
    { 656, L"WM_IME_KEYDOWN" },
    { 657, L"WM_IMEKEYUP" },
    { 657, L"WM_IME_KEYUP" },
    { 672, L"WM_NCMOUSEHOVER" },
    { 673, L"WM_MOUSEHOVER" },
    { 674, L"WM_NCMOUSELEAVE" },
    { 675, L"WM_MOUSELEAVE" },
    { 768, L"WM_CUT" },
    { 769, L"WM_COPY" },
    { 770, L"WM_PASTE" },
    { 771, L"WM_CLEAR" },
    { 772, L"WM_UNDO" },
    { 773, L"WM_RENDERFORMAT" },
    { 774, L"WM_RENDERALLFORMATS" },
    { 775, L"WM_DESTROYCLIPBOARD" },
    { 776, L"WM_DRAWCLIPBOARD" },
    { 777, L"WM_PAINTCLIPBOARD" },
    { 778, L"WM_VSCROLLCLIPBOARD" },
    { 779, L"WM_SIZECLIPBOARD" },
    { 780, L"WM_ASKCBFORMATNAME" },
    { 781, L"WM_CHANGECBCHAIN" },
    { 782, L"WM_HSCROLLCLIPBOARD" },
    { 783, L"WM_QUERYNEWPALETTE" },
    { 784, L"WM_PALETTEISCHANGING" },
    { 785, L"WM_PALETTECHANGED" },
    { 786, L"WM_HOTKEY" },
    { 791, L"WM_PRINT" },
    { 792, L"WM_PRINTCLIENT" },
    { 793, L"WM_APPCOMMAND" },
    { 856, L"WM_HANDHELDFIRST" },
    { 863, L"WM_HANDHELDLAST" },
    { 864, L"WM_AFXFIRST" },
    { 895, L"WM_AFXLAST" },
    { 896, L"WM_PENWINFIRST" },
    { 897, L"WM_RCRESULT" },
    { 898, L"WM_HOOKRCRESULT" },
    { 899, L"WM_GLOBALRCCHANGE" },
    { 899, L"WM_PENMISCINFO" },
    { 900, L"WM_SKB" },
    { 901, L"WM_HEDITCTL" },
    { 901, L"WM_PENCTL" },
    { 902, L"WM_PENMISC" },
    { 903, L"WM_CTLINIT" },
    { 904, L"WM_PENEVENT" },
    { 911, L"WM_PENWINLAST" },
    { 1024, L"WM_USER" }
};

/**
static const char * const MessageTypeNames[SPY_MAX_MSGNUM + 1] =
{
    "WM_NULL",                  // 0x00 
    "WM_CREATE",
    "WM_DESTROY",
    "WM_MOVE",
    "wm_sizewait",
    "WM_SIZE",
    "WM_ACTIVATE",
    "WM_SETFOCUS",
    "WM_KILLFOCUS",
    "WM_SETVISIBLE",
    "WM_ENABLE",
    "WM_SETREDRAW",
    "WM_SETTEXT",
    "WM_GETTEXT",
    "WM_GETTEXTLENGTH",
    "WM_PAINT",
    "WM_CLOSE",                 // 0x10 
    "WM_QUERYENDSESSION",
    "WM_QUIT",
    "WM_QUERYOPEN",
    "WM_ERASEBKGND",
    "WM_SYSCOLORCHANGE",
    "WM_ENDSESSION",
    "wm_systemerror",
    "WM_SHOWWINDOW",
    "WM_CTLCOLOR",
    "WM_WININICHANGE",
    "WM_DEVMODECHANGE",
    "WM_ACTIVATEAPP",
    "WM_FONTCHANGE",
    "WM_TIMECHANGE",
    "WM_CANCELMODE",
    "WM_SETCURSOR",             // 0x20 
    "WM_MOUSEACTIVATE",
    "WM_CHILDACTIVATE",
    "WM_QUEUESYNC",
    "WM_GETMINMAXINFO",
    "wm_unused3",
    "wm_painticon",
    "WM_ICONERASEBKGND",
    "WM_NEXTDLGCTL",
    "wm_alttabactive",
    "WM_SPOOLERSTATUS",
    "WM_DRAWITEM",
    "WM_MEASUREITEM",
    "WM_DELETEITEM",
    "WM_VKEYTOITEM",
    "WM_CHARTOITEM",
    "WM_SETFONT",               // 0x30 
    "WM_GETFONT",
    "WM_SETHOTKEY",
    "WM_GETHOTKEY",
    "wm_filesyschange",
    "wm_isactiveicon",
    "wm_queryparkicon",
    "WM_QUERYDRAGICON",
    "wm_querysavestate",
    "WM_COMPAREITEM",
    "wm_testing",
    NULL,
    NULL,
    "WM_GETOBJECT",             // 0x3d 
    "wm_activateshellwindow",
    NULL,

    NULL,                       // 0x40 
    "wm_compacting", NULL, NULL,
    "WM_COMMNOTIFY", NULL,
    "WM_WINDOWPOSCHANGING",     // 0x0046 
    "WM_WINDOWPOSCHANGED",      // 0x0047 
    "WM_POWER", NULL,
    "WM_COPYDATA",
    "WM_CANCELJOURNAL", NULL, NULL,
    "WM_NOTIFY", NULL,

    // 0x0050 
    "WM_INPUTLANGCHANGEREQUEST",
    "WM_INPUTLANGCHANGE",
    "WM_TCARD",
    "WM_HELP",
    "WM_USERCHANGED",
    "WM_NOTIFYFORMAT", NULL, NULL,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,

    // 0x0060 
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,

    // 0x0070 
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
    NULL, NULL, NULL,
    "WM_CONTEXTMENU",
    "WM_STYLECHANGING",
    "WM_STYLECHANGED",
    "WM_DISPLAYCHANGE",
    "WM_GETICON",

    "WM_SETICON",               // 0x0080 
    "WM_NCCREATE",              // 0x0081 
    "WM_NCDESTROY",             // 0x0082 
    "WM_NCCALCSIZE",            // 0x0083 
    "WM_NCHITTEST",             // 0x0084 
    "WM_NCPAINT",               // 0x0085 
    "WM_NCACTIVATE",            // 0x0086 
    "WM_GETDLGCODE",            // 0x0087 
    "WM_SYNCPAINT",
    "WM_SYNCTASK", NULL, NULL, NULL, NULL, NULL, NULL,

    // 0x0090 
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,

    // 0x00A0 
    "WM_NCMOUSEMOVE",           // 0x00a0 
    "WM_NCLBUTTONDOWN",         // 0x00a1 
    "WM_NCLBUTTONUP",           // 0x00a2 
    "WM_NCLBUTTONDBLCLK",       // 0x00a3 
    "WM_NCRBUTTONDOWN",         // 0x00a4 
    "WM_NCRBUTTONUP",           // 0x00a5 
    "WM_NCRBUTTONDBLCLK",       // 0x00a6 
    "WM_NCMBUTTONDOWN",         // 0x00a7 
    "WM_NCMBUTTONUP",           // 0x00a8 
    "WM_NCMBUTTONDBLCLK",       // 0x00a9 
    NULL,                       // 0x00aa 
    "WM_NCXBUTTONDOWN",         // 0x00ab 
    "WM_NCXBUTTONUP",           // 0x00ac 
    "WM_NCXBUTTONDBLCLK",       // 0x00ad 
    NULL,                       // 0x00ae 
    NULL,                       // 0x00af 

    // 0x00B0 - Win32 Edit controls 
    "EM_GETSEL",                // 0x00b0 
    "EM_SETSEL",                // 0x00b1 
    "EM_GETRECT",               // 0x00b2 
    "EM_SETRECT",               // 0x00b3 
    "EM_SETRECTNP",             // 0x00b4 
    "EM_SCROLL",                // 0x00b5 
    "EM_LINESCROLL",            // 0x00b6 
    "EM_SCROLLCARET",           // 0x00b7 
    "EM_GETMODIFY",             // 0x00b8 
    "EM_SETMODIFY",             // 0x00b9 
    "EM_GETLINECOUNT",          // 0x00ba 
    "EM_LINEINDEX",             // 0x00bb 
    "EM_SETHANDLE",             // 0x00bc 
    "EM_GETHANDLE",             // 0x00bd 
    "EM_GETTHUMB",              // 0x00be 
    NULL,                       // 0x00bf 

    NULL,                       // 0x00c0 
    "EM_LINELENGTH",            // 0x00c1 
    "EM_REPLACESEL",            // 0x00c2 
    NULL,                       // 0x00c3 
    "EM_GETLINE",               // 0x00c4 
    "EM_LIMITTEXT",             // 0x00c5 
    "EM_CANUNDO",               // 0x00c6 
    "EM_UNDO",                  // 0x00c7 
    "EM_FMTLINES",              // 0x00c8 
    "EM_LINEFROMCHAR",          // 0x00c9 
    NULL,                       // 0x00ca 
    "EM_SETTABSTOPS",           // 0x00cb 
    "EM_SETPASSWORDCHAR",       // 0x00cc 
    "EM_EMPTYUNDOBUFFER",       // 0x00cd 
    "EM_GETFIRSTVISIBLELINE",   // 0x00ce 
    "EM_SETREADONLY",           // 0x00cf 

    "EM_SETWORDBREAKPROC",      // 0x00d0 
    "EM_GETWORDBREAKPROC",      // 0x00d1 
    "EM_GETPASSWORDCHAR",       // 0x00d2 
    "EM_SETMARGINS",            // 0x00d3 
    "EM_GETMARGINS",            // 0x00d4 
    "EM_GETLIMITTEXT",          // 0x00d5 
    "EM_POSFROMCHAR",           // 0x00d6 
    "EM_CHARFROMPOS",           // 0x00d7 
    "EM_SETIMESTATUS",          // 0x00d8 
    "EM_GETIMESTATUS",          // 0x00d9 
    NULL, NULL, NULL, NULL, NULL, NULL,

    // 0x00E0 - Win32 Scrollbars 
    "SBM_SETPOS",               // 0x00e0 
    "SBM_GETPOS",               // 0x00e1 
    "SBM_SETRANGE",             // 0x00e2 
    "SBM_GETRANGE",             // 0x00e3 
    "SBM_ENABLE_ARROWS",        // 0x00e4 
    NULL,
    "SBM_SETRANGEREDRAW",       // 0x00e6 
    NULL, NULL,
    "SBM_SETSCROLLINFO",        // 0x00e9 
    "SBM_GETSCROLLINFO",        // 0x00ea 
    NULL, NULL, NULL, NULL, NULL,

    // 0x00F0 - Win32 Buttons 
    "BM_GETCHECK",              // 0x00f0 
    "BM_SETCHECK",              // 0x00f1 
    "BM_GETSTATE",              // 0x00f2 
    "BM_SETSTATE",              // 0x00f3 
    "BM_SETSTYLE",              // 0x00f4 
    "BM_CLICK",                 // 0x00f5 
    "BM_GETIMAGE",              // 0x00f6 
    "BM_SETIMAGE",              // 0x00f7 
    NULL, NULL, NULL, NULL, NULL, NULL,
    "WM_INPUT_DEVICE_CHANGE",   // 0x00fe 
    "WM_INPUT",                 // 0x00ff 

    "WM_KEYDOWN",               // 0x0100 
    "WM_KEYUP",                 // 0x0101 
    "WM_CHAR",                  // 0x0102 
    "WM_DEADCHAR",              // 0x0103 
    "WM_SYSKEYDOWN",            // 0x0104 
    "WM_SYSKEYUP",              // 0x0105 
    "WM_SYSCHAR",               // 0x0106 
    "WM_SYSDEADCHAR",           // 0x0107 
    NULL,
    "WM_UNICHAR",               // 0x0109 
    "WM_CONVERTREQUEST",        // 0x010a 
    "WM_CONVERTRESULT",         // 0x010b 
    "WM_INTERIM",               // 0x010c 
    "WM_IME_STARTCOMPOSITION",  // 0x010d 
    "WM_IME_ENDCOMPOSITION",    // 0x010e 
    "WM_IME_COMPOSITION",       // 0x010f 

    "WM_INITDIALOG",            // 0x0110 
    "WM_COMMAND",               // 0x0111 
    "WM_SYSCOMMAND",            // 0x0112 
    "WM_TIMER",                 // 0x0113 
    "WM_HSCROLL",               // 0x0114 
    "WM_VSCROLL",               // 0x0115 
    "WM_INITMENU",              // 0x0116 
    "WM_INITMENUPOPUP",         // 0x0117 
    "WM_SYSTIMER",              // 0x0118 
    NULL, NULL, NULL, NULL, NULL, NULL,
    "WM_MENUSELECT",            // 0x011f 

    "WM_MENUCHAR",              // 0x0120 
    "WM_ENTERIDLE",             // 0x0121 

    "WM_MENURBUTTONUP",         // 0x0122 
    "WM_MENUDRAG",              // 0x0123 
    "WM_MENUGETOBJECT",         // 0x0124 
    "WM_UNINITMENUPOPUP",       // 0x0125 
    "WM_MENUCOMMAND",           // 0x0126 
    "WM_CHANGEUISTATE",         // 0x0127 
    "WM_UPDATEUISTATE",         // 0x0128 
    "WM_QUERYUISTATE",          // 0x0129 

    NULL, NULL, NULL, NULL, NULL, NULL,

    // 0x0130 
    NULL,
    "WM_LBTRACKPOINT",          // 0x0131 
    "WM_CTLCOLORMSGBOX",        // 0x0132 
    "WM_CTLCOLOREDIT",          // 0x0133 
    "WM_CTLCOLORLISTBOX",       // 0x0134 
    "WM_CTLCOLORBTN",           // 0x0135 
    "WM_CTLCOLORDLG",           // 0x0136 
    "WM_CTLCOLORSCROLLBAR",     // 0x0137 
    "WM_CTLCOLORSTATIC",        // 0x0138 
    NULL, NULL, NULL, NULL, NULL, NULL, NULL,

    // 0x0140 - Win32 Comboboxes 
    "CB_GETEDITSEL",            // 0x0140 
    "CB_LIMITTEXT",             // 0x0141 
    "CB_SETEDITSEL",            // 0x0142 
    "CB_ADDSTRING",             // 0x0143 
    "CB_DELETESTRING",          // 0x0144 
    "CB_DIR",                   // 0x0145 
    "CB_GETCOUNT",              // 0x0146 
    "CB_GETCURSEL",             // 0x0147 
    "CB_GETLBTEXT",             // 0x0148 
    "CB_GETLBTEXTLEN",          // 0x0149 
    "CB_INSERTSTRING",          // 0x014a 
    "CB_RESETCONTENT",          // 0x014b 
    "CB_FINDSTRING",            // 0x014c 
    "CB_SELECTSTRING",          // 0x014d 
    "CB_SETCURSEL",             // 0x014e 
    "CB_SHOWDROPDOWN",          // 0x014f 

    "CB_GETITEMDATA",           // 0x0150 
    "CB_SETITEMDATA",           // 0x0151 
    "CB_GETDROPPEDCONTROLRECT", // 0x0152 
    "CB_SETITEMHEIGHT",         // 0x0153 
    "CB_GETITEMHEIGHT",         // 0x0154 
    "CB_SETEXTENDEDUI",         // 0x0155 
    "CB_GETEXTENDEDUI",         // 0x0156 
    "CB_GETDROPPEDSTATE",       // 0x0157 
    "CB_FINDSTRINGEXACT",       // 0x0158 
    "CB_SETLOCALE",             // 0x0159 
    "CB_GETLOCALE",             // 0x015a 
    "CB_GETTOPINDEX",           // 0x015b 
    "CB_SETTOPINDEX",           // 0x015c 
    "CB_GETHORIZONTALEXTENT",   // 0x015d 
    "CB_SETHORIZONTALEXTENT",   // 0x015e 
    "CB_GETDROPPEDWIDTH",       // 0x015f 

    "CB_SETDROPPEDWIDTH",       // 0x0160 
    "CB_INITSTORAGE",           // 0x0161 
    NULL, NULL, NULL, NULL, NULL, NULL,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,

    // 0x0170 - Win32 Static controls 
    "STM_SETICON",              // 0x0170 
    "STM_GETICON",              // 0x0171 
    "STM_SETIMAGE",             // 0x0172 
    "STM_GETIMAGE",             // 0x0173 
    NULL, NULL, NULL, NULL,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,

    // 0x0180 - Win32 Listboxes 
    "LB_ADDSTRING",             // 0x0180 
    "LB_INSERTSTRING",          // 0x0181 
    "LB_DELETESTRING",          // 0x0182 
    "LB_SELITEMRANGEEX",        // 0x0183 
    "LB_RESETCONTENT",          // 0x0184 
    "LB_SETSEL",                // 0x0185 
    "LB_SETCURSEL",             // 0x0186 
    "LB_GETSEL",                // 0x0187 
    "LB_GETCURSEL",             // 0x0188 
    "LB_GETTEXT",               // 0x0189 
    "LB_GETTEXTLEN",            // 0x018a 
    "LB_GETCOUNT",              // 0x018b 
    "LB_SELECTSTRING",          // 0x018c 
    "LB_DIR",                   // 0x018d 
    "LB_GETTOPINDEX",           // 0x018e 
    "LB_FINDSTRING",            // 0x018f 

    "LB_GETSELCOUNT",           // 0x0190 
    "LB_GETSELITEMS",           // 0x0191 
    "LB_SETTABSTOPS",           // 0x0192 
    "LB_GETHORIZONTALEXTENT",   // 0x0193 
    "LB_SETHORIZONTALEXTENT",   // 0x0194 
    "LB_SETCOLUMNWIDTH",        // 0x0195 
    "LB_ADDFILE",               // 0x0196 
    "LB_SETTOPINDEX",           // 0x0197 
    "LB_GETITEMRECT",           // 0x0198 
    "LB_GETITEMDATA",           // 0x0199 
    "LB_SETITEMDATA",           // 0x019a 
    "LB_SELITEMRANGE",          // 0x019b 
    "LB_SETANCHORINDEX",        // 0x019c 
    "LB_GETANCHORINDEX",        // 0x019d 
    "LB_SETCARETINDEX",         // 0x019e 
    "LB_GETCARETINDEX",         // 0x019f 

    "LB_SETITEMHEIGHT",         // 0x01a0 
    "LB_GETITEMHEIGHT",         // 0x01a1 
    "LB_FINDSTRINGEXACT",       // 0x01a2 
    "LB_CARETON",               // 0x01a3 
    "LB_CARETOFF",              // 0x01a4 
    "LB_SETLOCALE",             // 0x01a5 
    "LB_GETLOCALE",             // 0x01a6 
    "LB_SETCOUNT",              // 0x01a7 
    "LB_INITSTORAGE",           // 0x01a8 
    "LB_ITEMFROMPOINT",         // 0x01a9 
    NULL, NULL, NULL, NULL, NULL, NULL,

    // 0x01B0 
    NULL, NULL,
    "LB_GETLISTBOXINFO",         // 0x01b2 
    NULL, NULL, NULL, NULL, NULL,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,

    // 0x01C0 
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,

    // 0x01D0 
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,

    // 0x01E0 
    NULL,
    "MN_GETHMENU",              // 0x01E1 
    NULL, NULL, NULL, NULL, NULL, NULL,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,

    // 0x01F0 
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,

    "WM_MOUSEMOVE",             // 0x0200 
    "WM_LBUTTONDOWN",           // 0x0201 
    "WM_LBUTTONUP",             // 0x0202 
    "WM_LBUTTONDBLCLK",         // 0x0203 
    "WM_RBUTTONDOWN",           // 0x0204 
    "WM_RBUTTONUP",             // 0x0205 
    "WM_RBUTTONDBLCLK",         // 0x0206 
    "WM_MBUTTONDOWN",           // 0x0207 
    "WM_MBUTTONUP",             // 0x0208 
    "WM_MBUTTONDBLCLK",         // 0x0209 
    "WM_MOUSEWHEEL",            // 0x020A 
    "WM_XBUTTONDOWN",           // 0x020B 
    "WM_XBUTTONUP",             // 0x020C 
    "WM_XBUTTONDBLCLK",         // 0x020D 
    "WM_MOUSEHWHEEL",           // 0x020E 
    NULL,

    "WM_PARENTNOTIFY",          // 0x0210 
    "WM_ENTERMENULOOP",         // 0x0211 
    "WM_EXITMENULOOP",          // 0x0212 
    "WM_NEXTMENU",              // 0x0213 
    "WM_SIZING",
    "WM_CAPTURECHANGED",
    "WM_MOVING", NULL,
    "WM_POWERBROADCAST",
    "WM_DEVICECHANGE", NULL, NULL, NULL, NULL, NULL, NULL,

    "WM_MDICREATE",             // 0x0220 
    "WM_MDIDESTROY",            // 0x0221 
    "WM_MDIACTIVATE",           // 0x0222 
    "WM_MDIRESTORE",            // 0x0223 
    "WM_MDINEXT",               // 0x0224 
    "WM_MDIMAXIMIZE",           // 0x0225 
    "WM_MDITILE",               // 0x0226 
    "WM_MDICASCADE",            // 0x0227 
    "WM_MDIICONARRANGE",        // 0x0228 
    "WM_MDIGETACTIVE",          // 0x0229 

    "WM_DROPOBJECT",
    "WM_QUERYDROPOBJECT",
    "WM_BEGINDRAG",
    "WM_DRAGLOOP",
    "WM_DRAGSELECT",
    "WM_DRAGMOVE",

    // 0x0230
    "WM_MDISETMENU",            // 0x0230 
    "WM_ENTERSIZEMOVE",         // 0x0231 
    "WM_EXITSIZEMOVE",          // 0x0232 
    "WM_DROPFILES",             // 0x0233 
    "WM_MDIREFRESHMENU", NULL, NULL, NULL,
    // 0x0238
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,

    // 0x0240 
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,

    // 0x0250 
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,

    // 0x0260 
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,

    // 0x0280 
    NULL,
    "WM_IME_SETCONTEXT",        // 0x0281 
    "WM_IME_NOTIFY",            // 0x0282 
    "WM_IME_CONTROL",           // 0x0283 
    "WM_IME_COMPOSITIONFULL",   // 0x0284 
    "WM_IME_SELECT",            // 0x0285 
    "WM_IME_CHAR",              // 0x0286 
    NULL,
    "WM_IME_REQUEST",           // 0x0288 
    NULL, NULL, NULL, NULL, NULL, NULL, NULL,
    "WM_IME_KEYDOWN",           // 0x0290 
    "WM_IME_KEYUP",             // 0x0291 
    NULL, NULL, NULL, NULL, NULL, NULL,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,

    // 0x02a0 
    "WM_NCMOUSEHOVER",          // 0x02A0 
    "WM_MOUSEHOVER",            // 0x02A1 
    "WM_NCMOUSELEAVE",          // 0x02A2 
    "WM_MOUSELEAVE",            // 0x02A3 
    NULL, NULL, NULL, NULL, NULL, NULL,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL,
    "WM_WTSSESSION_CHANGE",     // 0x02B1 
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
    NULL, NULL, NULL, NULL, NULL, NULL,

    // 0x02c0 
    "WM_TABLET_FIRST",          // 0x02c0 
    "WM_TABLET_FIRST+1",        // 0x02c1 
    "WM_TABLET_FIRST+2",        // 0x02c2 
    "WM_TABLET_FIRST+3",        // 0x02c3 
    "WM_TABLET_FIRST+4",        // 0x02c4 
    "WM_TABLET_FIRST+5",        // 0x02c5 
    "WM_TABLET_FIRST+7",        // 0x02c6 
    "WM_TABLET_FIRST+8",        // 0x02c7 
    "WM_TABLET_FIRST+9",        // 0x02c8 
    "WM_TABLET_FIRST+10",       // 0x02c9 
    "WM_TABLET_FIRST+11",       // 0x02ca 
    "WM_TABLET_FIRST+12",       // 0x02cb 
    "WM_TABLET_FIRST+13",       // 0x02cc 
    "WM_TABLET_FIRST+14",       // 0x02cd 
    "WM_TABLET_FIRST+15",       // 0x02ce 
    "WM_TABLET_FIRST+16",       // 0x02cf 
    "WM_TABLET_FIRST+17",       // 0x02d0 
    "WM_TABLET_FIRST+18",       // 0x02d1 
    "WM_TABLET_FIRST+19",       // 0x02d2 
    "WM_TABLET_FIRST+20",       // 0x02d3 
    "WM_TABLET_FIRST+21",       // 0x02d4 
    "WM_TABLET_FIRST+22",       // 0x02d5 
    "WM_TABLET_FIRST+23",       // 0x02d6 
    "WM_TABLET_FIRST+24",       // 0x02d7 
    "WM_TABLET_FIRST+25",       // 0x02d8 
    "WM_TABLET_FIRST+26",       // 0x02d9 
    "WM_TABLET_FIRST+27",       // 0x02da 
    "WM_TABLET_FIRST+28",       // 0x02db 
    "WM_TABLET_FIRST+29",       // 0x02dc 
    "WM_TABLET_FIRST+30",       // 0x02dd 
    "WM_TABLET_FIRST+31",       // 0x02de 
    "WM_TABLET_LAST",           // 0x02df 

    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,

    "WM_CUT",                   // 0x0300 
    "WM_COPY",
    "WM_PASTE",
    "WM_CLEAR",
    "WM_UNDO",
    "WM_RENDERFORMAT",
    "WM_RENDERALLFORMATS",
    "WM_DESTROYCLIPBOARD",
    "WM_DRAWCLIPBOARD",
    "WM_PAINTCLIPBOARD",
    "WM_VSCROLLCLIPBOARD",
    "WM_SIZECLIPBOARD",
    "WM_ASKCBFORMATNAME",
    "WM_CHANGECBCHAIN",
    "WM_HSCROLLCLIPBOARD",
    "WM_QUERYNEWPALETTE",       // 0x030f

    "WM_PALETTEISCHANGING",
    "WM_PALETTECHANGED",
    "WM_HOTKEY",                // 0x0312 
    "WM_POPUPSYSTEMMENU",       // 0x0313 
    NULL, NULL, NULL,
    "WM_PRINT",                 // 0x0317 
    "WM_PRINTCLIENT",           // 0x0318 
    "WM_APPCOMMAND",            // 0x0319 
    "WM_THEMECHANGED",          // 0x031A 
    NULL, NULL,
    "WM_CLIPBOARDUPDATE",       // 0x031D 
    "WM_DWMCOMPOSITIONCHANGED", // 0x031E 
    "WM_DWMNCRENDERINGCHANGED", // 0x031F 

    "WM_DWMCOLORIZATIONCOLORCHANGED", // 0x0320 
    "WM_DWMWINDOWMAXIMIZEDCHANGE", // 0x0321 
    NULL, NULL, NULL, NULL, NULL, NULL,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,

    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL,
    "WM_GETTITLEBARINFOEX",     // 0x033F 

    // 0x0340 
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
    // 0x0350 
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
    "WM_HANDHELDFIRST",     // 0x0358 
    "WM_HANDHELDFIRST+1",   // 0x0359 
    "WM_HANDHELDFIRST+2",   // 0x035A 
    "WM_HANDHELDFIRST+3",   // 0x035B 
    "WM_HANDHELDFIRST+4",   // 0x035C 
    "WM_HANDHELDFIRST+5",   // 0x035D 
    "WM_HANDHELDFIRST+6",   // 0x035E 
    "WM_HANDHELDLAST",      // 0x035F 

    "WM_QUERYAFXWNDPROC",   //  0x0360 WM_AFXFIRST 
    "WM_SIZEPARENT",        //  0x0361 
    "WM_SETMESSAGESTRING",  //  0x0362 
    "WM_IDLEUPDATECMDUI",   //  0x0363 
    "WM_INITIALUPDATE",     //  0x0364 
    "WM_COMMANDHELP",       //  0x0365 
    "WM_HELPHITTEST",       //  0x0366 
    "WM_EXITHELPMODE",      //  0x0367 
    "WM_RECALCPARENT",      //  0x0368 
    "WM_SIZECHILD",         //  0x0369 
    "WM_KICKIDLE",          //  0x036A 
    "WM_QUERYCENTERWND",    //  0x036B 
    "WM_DISABLEMODAL",      //  0x036C 
    "WM_FLOATSTATUS",       //  0x036D 
    "WM_ACTIVATETOPLEVEL",  //  0x036E 
    "WM_QUERY3DCONTROLS",   //  0x036F 
    NULL,NULL,NULL,
    "WM_SOCKET_NOTIFY",     //  0x0373 
    "WM_SOCKET_DEAD",       //  0x0374 
    "WM_POPMESSAGESTRING",  //  0x0375 
    "WM_OCC_LOADFROMSTREAM",     // 0x0376 
    "WM_OCC_LOADFROMSTORAGE",    // 0x0377 
    "WM_OCC_INITNEW",            // 0x0378 
    "WM_QUEUE_SENTINEL",         // 0x0379 
    "WM_OCC_LOADFROMSTREAM_EX",  // 0x037A 
    "WM_OCC_LOADFROMSTORAGE_EX", // 0x037B 

    NULL,NULL,NULL,
    "WM_AFXLAST",               // 0x037F 

    "WM_PENWINFIRST",           // 0x0380 
    "WM_RCRESULT",              // 0x0381 
    "WM_HOOKRCRESULT",          // 0x0382 
    "WM_GLOBALRCCHANGE",        // 0x0383 
    "WM_SKB",                   // 0x0384 
    "WM_HEDITCTL",              // 0x0385 
    NULL, NULL,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL,
    "WM_PENWINLAST",            // 0x038F 

    "WM_COALESCE_FIRST",        // 0x0390 
    NULL, NULL, NULL, NULL, NULL, NULL, NULL,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL,
    "WM_COALESCE_LAST",         // 0x039F 

    // 0x03a0 
    "MM_JOY1MOVE",
    "MM_JOY2MOVE",
    "MM_JOY1ZMOVE",
    "MM_JOY2ZMOVE",
                            NULL, NULL, NULL, NULL,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,

    // 0x03b0 
    NULL, NULL, NULL, NULL, NULL,
    "MM_JOY1BUTTONDOWN",
    "MM_JOY2BUTTONDOWN",
    "MM_JOY1BUTTONUP",
    "MM_JOY2BUTTONUP",
    "MM_MCINOTIFY",       // 0x03B9 
                NULL,
    "MM_WOM_OPEN",        // 0x03BB 
    "MM_WOM_CLOSE",       // 0x03BC 
    "MM_WOM_DONE",        // 0x03BD 
    "MM_WIM_OPEN",        // 0x03BE 
    "MM_WIM_CLOSE",       // 0x03BF 

    // 0x03c0 
    "MM_WIM_DATA",        // 0x03C0 
    "MM_MIM_OPEN",        // 0x03C1 
    "MM_MIM_CLOSE",       // 0x03C2 
    "MM_MIM_DATA",        // 0x03C3 
    "MM_MIM_LONGDATA",    // 0x03C4 
    "MM_MIM_ERROR",       // 0x03C5 
    "MM_MIM_LONGERROR",   // 0x03C6 
    "MM_MOM_OPEN",        // 0x03C7 
    "MM_MOM_CLOSE",       // 0x03C8 
    "MM_MOM_DONE",        // 0x03C9 
    "MM_MOM_POSITIONCB",  // 0x03CA 
    "MM_MCISIGNAL",       // 0x03CB 
    "MM_MIM_MOREDATA",    // 0x03CC 
                                  NULL, NULL, NULL,

    "MM_MIXM_LINE_CHANGE",
    "MM_MIXM_CONTROL_CHANGE",
                NULL, NULL, NULL, NULL, NULL, NULL,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,


    "WM_DDE_INITIATE",  // 0x3E0 
    "WM_DDE_TERMINATE", // 0x3E1 
    "WM_DDE_ADVISE",    // 0x3E2 
    "WM_DDE_UNADVISE",  // 0x3E3 
    "WM_DDE_ACK",       // 0x3E4 
    "WM_DDE_DATA",      // 0x3E5 
    "WM_DDE_REQUEST",   // 0x3E6 
    "WM_DDE_POKE",      // 0x3E7 
    "WM_DDE_EXECUTE",   // 0x3E8 
    NULL, NULL, NULL, NULL, NULL, NULL, NULL,

    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,

    "WM_USER"                  
};


#define SPY_MAX_LVMMSGNUM   182
static const char * const LVMMessageTypeNames[SPY_MAX_LVMMSGNUM + 1] =
{
    "LVM_GETBKCOLOR",          
    "LVM_SETBKCOLOR",
    "LVM_GETIMAGELIST",
    "LVM_SETIMAGELIST",
    "LVM_GETITEMCOUNT",
    "LVM_GETITEMA",
    "LVM_SETITEMA",
    "LVM_INSERTITEMA",
    "LVM_DELETEITEM",
    "LVM_DELETEALLITEMS",
    "LVM_GETCALLBACKMASK",
    "LVM_SETCALLBACKMASK",
    "LVM_GETNEXTITEM",
    "LVM_FINDITEMA",
    "LVM_GETITEMRECT",
    "LVM_SETITEMPOSITION",
    "LVM_GETITEMPOSITION",
    "LVM_GETSTRINGWIDTHA",
    "LVM_HITTEST",
    "LVM_ENSUREVISIBLE",
    "LVM_SCROLL",
    "LVM_REDRAWITEMS",
    "LVM_ARRANGE",
    "LVM_EDITLABELA",
    "LVM_GETEDITCONTROL",
    "LVM_GETCOLUMNA",
    "LVM_SETCOLUMNA",
    "LVM_INSERTCOLUMNA",
    "LVM_DELETECOLUMN",
    "LVM_GETCOLUMNWIDTH",
    "LVM_SETCOLUMNWIDTH",
    "LVM_GETHEADER",
    NULL,
    "LVM_CREATEDRAGIMAGE",
    "LVM_GETVIEWRECT",
    "LVM_GETTEXTCOLOR",
    "LVM_SETTEXTCOLOR",
    "LVM_GETTEXTBKCOLOR",
    "LVM_SETTEXTBKCOLOR",
    "LVM_GETTOPINDEX",
    "LVM_GETCOUNTPERPAGE",
    "LVM_GETORIGIN",
    "LVM_UPDATE",
    "LVM_SETITEMSTATE",
    "LVM_GETITEMSTATE",
    "LVM_GETITEMTEXTA",
    "LVM_SETITEMTEXTA",
    "LVM_SETITEMCOUNT",
    "LVM_SORTITEMS",
    "LVM_SETITEMPOSITION32",
    "LVM_GETSELECTEDCOUNT",
    "LVM_GETITEMSPACING",
    "LVM_GETISEARCHSTRINGA",
    "LVM_SETICONSPACING",
    "LVM_SETEXTENDEDLISTVIEWSTYLE",
    "LVM_GETEXTENDEDLISTVIEWSTYLE",
    "LVM_GETSUBITEMRECT",
    "LVM_SUBITEMHITTEST",
    "LVM_SETCOLUMNORDERARRAY",
    "LVM_GETCOLUMNORDERARRAY",
    "LVM_SETHOTITEM",
    "LVM_GETHOTITEM",
    "LVM_SETHOTCURSOR",
    "LVM_GETHOTCURSOR",
    "LVM_APPROXIMATEVIEWRECT",
    "LVM_SETWORKAREAS",
    "LVM_GETSELECTIONMARK",
    "LVM_SETSELECTIONMARK",
    "LVM_SETBKIMAGEA",
    "LVM_GETBKIMAGEA",
    "LVM_GETWORKAREAS",
    "LVM_SETHOVERTIME",
    "LVM_GETHOVERTIME",
    "LVM_GETNUMBEROFWORKAREAS",
    "LVM_SETTOOLTIPS",
    "LVM_GETITEMW",
    "LVM_SETITEMW",
    "LVM_INSERTITEMW",
    "LVM_GETTOOLTIPS",
    NULL,
    NULL,
    NULL,
    NULL,
    "LVM_FINDITEMW",
    NULL,
    NULL,
    NULL,
    "LVM_GETSTRINGWIDTHW",
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    "LVM_GETCOLUMNW",
    "LVM_SETCOLUMNW",
    "LVM_INSERTCOLUMNW",
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    "LVM_GETITEMTEXTW",
    "LVM_SETITEMTEXTW",
    "LVM_GETISEARCHSTRINGW",
    "LVM_EDITLABELW",
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    "LVM_SETBKIMAGEW",
    "LVM_GETBKIMAGEW",   
    "LVM_SETSELECTEDCOLUMN",
    "LVM_SETTILEWIDTH",
    "LVM_SETVIEW",
    "LVM_GETVIEW",
    NULL,
    "LVM_INSERTGROUP",
    NULL,
    "LVM_SETGROUPINFO",
    NULL,
    "LVM_GETGROUPINFO",
    "LVM_REMOVEGROUP",
    "LVM_MOVEGROUP",
    NULL,
    NULL,
    "LVM_MOVEITEMTOGROUP",
    "LVM_SETGROUPMETRICS",
    "LVM_GETGROUPMETRICS",
    "LVM_ENABLEGROUPVIEW",
    "LVM_SORTGROUPS",
    "LVM_INSERTGROUPSORTED",
    "LVM_REMOVEALLGROUPS",
    "LVM_HASGROUP",
    "LVM_SETTILEVIEWINFO",
    "LVM_GETTILEVIEWINFO",
    "LVM_SETTILEINFO",
    "LVM_GETTILEINFO",
    "LVM_SETINSERTMARK",
    "LVM_GETINSERTMARK",
    "LVM_INSERTMARKHITTEST",
    "LVM_GETINSERTMARKRECT",
    "LVM_SETINSERTMARKCOLOR",
    "LVM_GETINSERTMARKCOLOR",
    NULL,
    "LVM_SETINFOTIP",
    "LVM_GETSELECTEDCOLUMN",
    "LVM_ISGROUPVIEWENABLED",
    "LVM_GETOUTLINECOLOR",
    "LVM_SETOUTLINECOLOR",
    NULL,
    "LVM_CANCELEDITLABEL",
    "LVM_MAPINDEXTOID",
    "LVM_MAPIDTOINDEX",
    "LVM_ISITEMVISIBLE"
};


#define SPY_MAX_TVMSGNUM   65
static const char * const TVMessageTypeNames[SPY_MAX_TVMSGNUM + 1] =
{
    "TVM_INSERTITEMA",        
    "TVM_DELETEITEM",
    "TVM_EXPAND",
    NULL,
    "TVM_GETITEMRECT",
    "TVM_GETCOUNT",
    "TVM_GETINDENT",
    "TVM_SETINDENT",
    "TVM_GETIMAGELIST",
    "TVM_SETIMAGELIST",
    "TVM_GETNEXTITEM",
    "TVM_SELECTITEM",
    "TVM_GETITEMA",
    "TVM_SETITEMA",
    "TVM_EDITLABELA",
    "TVM_GETEDITCONTROL",
    "TVM_GETVISIBLECOUNT",
    "TVM_HITTEST",
    "TVM_CREATEDRAGIMAGE",
    "TVM_SORTCHILDREN",
    "TVM_ENSUREVISIBLE",
    "TVM_SORTCHILDRENCB",
    "TVM_ENDEDITLABELNOW",
    "TVM_GETISEARCHSTRINGA",
    "TVM_SETTOOLTIPS",
    "TVM_GETTOOLTIPS",
    "TVM_SETINSERTMARK",
    "TVM_SETITEMHEIGHT",
    "TVM_GETITEMHEIGHT",
    "TVM_SETBKCOLOR",
    "TVM_SETTEXTCOLOR",
    "TVM_GETBKCOLOR",
    "TVM_GETTEXTCOLOR",
    "TVM_SETSCROLLTIME",
    "TVM_GETSCROLLTIME",
    "TVM_UNKNOWN35",
    "TVM_UNKNOWN36",
    "TVM_SETINSERTMARKCOLOR",
    "TVM_GETINSERTMARKCOLOR",
    "TVM_GETITEMSTATE",
    "TVM_SETLINECOLOR",
    "TVM_GETLINECOLOR",
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    "TVM_INSERTITEMW",
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    "TVM_GETITEMW",
    "TVM_SETITEMW",
    "TVM_GETISEARCHSTRINGW",
    "TVM_EDITLABELW"
};


#define SPY_MAX_HDMMSGNUM   19
static const char * const HDMMessageTypeNames[SPY_MAX_HDMMSGNUM + 1] =
{
    "HDM_GETITEMCOUNT",         
    "HDM_INSERTITEMA",
    "HDM_DELETEITEM",
    "HDM_GETITEMA",
    "HDM_SETITEMA",
    "HDM_LAYOUT",
    "HDM_HITTEST",
    "HDM_GETITEMRECT",
    "HDM_SETIMAGELIST",
    "HDM_GETIMAGELIST",
    "HDM_INSERTITEMW",
    "HDM_GETITEMW",
    "HDM_SETITEMW",
    NULL,
    NULL,
    "HDM_ORDERTOINDEX",
    "HDM_CREATEDRAGIMAGE",
    "GETORDERARRAYINDEX",
    "SETORDERARRAYINDEX",
    "SETHOTDIVIDER"
};


#define SPY_MAX_TCMMSGNUM   62
static const char * const TCMMessageTypeNames[SPY_MAX_TCMMSGNUM + 1] =
{
    NULL,             
    NULL,
    "TCM_SETIMAGELIST",
    "TCM_GETIMAGELIST",
    "TCM_GETITEMCOUNT",
    "TCM_GETITEMA",
    "TCM_SETITEMA",
    "TCM_INSERTITEMA",
    "TCM_DELETEITEM",
    "TCM_DELETEALLITEMS",
    "TCM_GETITEMRECT",
    "TCM_GETCURSEL",
    "TCM_SETCURSEL",
    "TCM_HITTEST",
    "TCM_SETITEMEXTRA",
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    "TCM_ADJUSTRECT",
    "TCM_SETITEMSIZE",
    "TCM_REMOVEIMAGE",
    "TCM_SETPADDING",
    "TCM_GETROWCOUNT",
    "TCM_GETTOOLTIPS",
    "TCM_SETTOOLTIPS",
    "TCM_GETCURFOCUS",
    "TCM_SETCURFOCUS",
    "TCM_SETMINTABWIDTH",
    "TCM_DESELECTALL",
    "TCM_HIGHLIGHTITEM",
    "TCM_SETEXTENDEDSTYLE",
    "TCM_GETEXTENDEDSTYLE",
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    "TCM_GETITEMW",
    "TCM_SETITEMW",
    "TCM_INSERTITEMW"
};

#define SPY_MAX_PGMMSGNUM   13
static const char * const PGMMessageTypeNames[SPY_MAX_PGMMSGNUM + 1] =
{
    NULL,              
    "PGM_SETCHILD",
    "PGM_RECALCSIZE",
    "PGM_FORWARDMOUSE",
    "PGM_SETBKCOLOR",
    "PGM_GETBKCOLOR",
    "PGM_SETBORDER",
    "PGM_GETBORDER",
    "PGM_SETPOS",
    "PGM_GETPOS",
    "PGM_SETBUTTONSIZE",
    "PGM_GETBUTTONSIZE",
    "PGM_GETBUTTONSTATE",
    "PGM_GETDROPTARGET"
};


#define SPY_MAX_CCMMSGNUM   9
static const char * const CCMMessageTypeNames[SPY_MAX_CCMMSGNUM + 1] =
{
    NULL,              
    "CCM_SETBKCOLOR",
    "CCM_SETCOLORSCHEME",
    "CCM_GETCOLORSCHEME",
    "CCM_GETDROPTARGET",
    "CCM_SETUNICODEFORMAT",
    "CCM_GETUNICODEFORMAT",
    "CCM_SETVERSION",
    "CCM_GETVERSION",
    "CCM_SETNOTIFYWINDOW"
};
*/

#define NUM_XMSGS ARRAYSIZE(xmsglist)

DWORD name2pid(LPWSTR ImageName) {
    HANDLE         hSnap;
    PROCESSENTRY32 pe32;
    DWORD          dwPid=0;
    
    // create snapshot of system
    hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if(hSnap == INVALID_HANDLE_VALUE) return 0;
    
    pe32.dwSize = sizeof(PROCESSENTRY32);

    // get first process
    if(Process32First(hSnap, &pe32)){
      do {
        if (lstrcmpi(ImageName, pe32.szExeFile)==0) {
          dwPid = pe32.th32ProcessID;
          break;
        }
      } while(Process32Next(hSnap, &pe32));
    }
    CloseHandle(hSnap);
    
    return dwPid;
}

// 
int main(int argc, char *argv[]) {
    int   i;
    HWND  hwnd;
    BYTE  buffer[64];
    DWORD len;
    
    hwnd = (HWND)strtoul(argv[1], NULL, 16);
    
    printf("Window handle : %p\n", (void*)hwnd);
    
    for(i=0;i<NUM_XMSGS;i++) {
      wprintf(L"Sending %s...\n", xmsglist[i].text);
      SendMessage(hwnd, xmsglist[i].code, 0x12345678, 0x12345678);
      Sleep(500);
    }
    return 0;
}
