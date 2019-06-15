@echo off
cl -nologo -Os xbin.cpp
echo.
cl -DCONSOLE -c -nologo -Os -O2 -Gm- -GR- -EHa -Oi -GS- payload.c
link /order:@conhost.txt /entry:GetWindowHandle /base:0 payload.obj -subsystem:console -nodefaultlib -stack:0x100000,0x100000
xbin payload.exe .text
move payload.exe64.bin ..\..\conhost\payload.bin
echo.
cl -DSUBCLASS -c -nologo -Os -O2 -Gm- -GR- -EHa -Oi -GS- payload.c
link /order:@propagate.txt /entry:SubclassProc /base:0 payload.obj -subsystem:console -nodefaultlib -stack:0x100000,0x100000
xbin payload.exe .text
move payload.exe64.bin ..\..\propagate\payload.bin
echo.
cl -DWINDOW -c -nologo -Os -O2 -Gm- -GR- -EHa -Oi -GS- payload.c
link /order:@extrabytes.txt /entry:WndProc /base:0 payload.obj -subsystem:console -nodefaultlib -stack:0x100000,0x100000
xbin payload.exe .text
move payload.exe64.bin ..\..\extrabytes\payload.bin
echo.
cl -DSVCCTRL -c -nologo -Os -O2 -Gm- -GR- -EHa -Oi -GS- payload.c
link /order:@svcctrl.txt /entry:Handler /base:0 payload.obj -subsystem:console -nodefaultlib -stack:0x100000,0x100000
xbin payload.exe .text
move payload.exe64.bin ..\..\svcctrl\payload.bin
echo.
cl -DALPC -c -nologo -Os -O2 -Gm- -GR- -EHa -Oi -GS- payload.c
link /order:@alpc.txt /entry:TpAlpcCallBack /base:0 payload.obj -subsystem:console -nodefaultlib -stack:0x100000,0x100000
xbin payload.exe .text
copy payload.exe64.bin ..\..\alpc\payload.bin
move payload.exe64.bin ..\..\spooler\payload.bin
echo.
cl -DWORDBREAK -c -nologo -Os -O2 -Gm- -GR- -EHa -Oi -GS- payload.c
link /order:@wordwarping.txt /entry:Editwordbreakproca /base:0 payload.obj -subsystem:console -nodefaultlib -stack:0x100000,0x100000
xbin payload.exe .text
move payload.exe64.bin ..\..\richedit\wordbreak.bin
echo.
cl -DHYPHENATE -c -nologo -Os -O2 -Gm- -GR- -EHa -Oi -GS- payload.c
link /order:@hyphentension.txt /entry:HyphenateProc /base:0 payload.obj -subsystem:console -nodefaultlib -stack:0x100000,0x100000
xbin payload.exe .text
move payload.exe64.bin ..\..\richedit\hyphenate.bin
echo.
cl -DAUTOCORRECT -c -nologo -Os -O2 -Gm- -GR- -EHa -Oi -GS- payload.c
link /order:@autocourgette.txt /entry:Autocorrectproc /base:0 payload.obj -subsystem:console -nodefaultlib -stack:0x100000,0x100000
xbin payload.exe .text
move payload.exe64.bin ..\..\richedit\autocorrect.bin
echo.
cl -DSTREAM -c -nologo -Os -O2 -Gm- -GR- -EHa -Oi -GS- payload.c
link /order:@streamception.txt /entry:Editstreamcallback /base:0 payload.obj -subsystem:console -nodefaultlib -stack:0x100000,0x100000
xbin payload.exe .text
move payload.exe64.bin ..\..\richedit\stream.bin
echo.
cl -DCLIPBOARD -c -nologo -Os -O2 -Gm- -GR- -EHa -Oi -GS- payload.c
link /order:@clipboard.txt /entry:OleGetClipboardData /base:0 payload.obj -subsystem:console -nodefaultlib -stack:0x100000,0x100000
xbin payload.exe .text
move payload.exe64.bin ..\..\richedit\clipboard.bin
echo.
cl -DLVCOMPARE -c -nologo -Os -O2 -Gm- -GR- -EHa -Oi -GS- payload.c
link /order:@listview.txt /entry:Pfnlvgroupcompare /base:0 payload.obj -subsystem:console -nodefaultlib -stack:0x100000,0x100000
xbin payload.exe .text
move payload.exe64.bin ..\..\richedit\listview.bin
echo.
cl -DTVCOMPARE -c -nologo -Os -O2 -Gm- -GR- -EHa -Oi -GS- payload.c
link /order:@treeview.txt /entry:TvCompareFunc /base:0 payload.obj -subsystem:console -nodefaultlib -stack:0x100000,0x100000
xbin payload.exe .text
move payload.exe64.bin ..\..\richedit\treeview.bin
echo.
cl -DRELEASE -c -nologo -Os -O2 -Gm- -GR- -EHa -Oi -GS- payload.c
link /order:@release.txt /entry:Release /base:0 payload.obj -subsystem:console -nodefaultlib -stack:0x100000,0x100000
xbin payload.exe .text
move payload.exe64.bin ..\..\clipboard\release.bin
echo.
cl -DWNF -c -nologo -Os -O2 -Gm- -GR- -EHa -Oi -GS- payload.c
link /order:@wnf.txt /entry:WnfCallback /base:0 payload.obj -subsystem:console -nodefaultlib -stack:0x100000,0x100000
xbin payload.exe .text
move payload.exe64.bin ..\..\wnf\payload.bin