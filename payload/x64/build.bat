@echo off
cl -nologo -Os xbin.cpp
echo.
cl -DCONSOLE -c -nologo -Os -O2 -Gm- -GR- -EHa -Oi -GS- payload.c
link /order:@conhost.txt /entry:GetWindowHandle /fixed payload.obj -subsystem:console -nodefaultlib -stack:0x100000,0x100000
xbin payload.exe .text
move payload.exe64.bin ..\..\conhost\payload.bin
echo.
cl -DSUBCLASS -c -nologo -Os -O2 -Gm- -GR- -EHa -Oi -GS- payload.c
link /order:@propagate.txt /entry:SubclassProc /fixed payload.obj -subsystem:console -nodefaultlib -stack:0x100000,0x100000
xbin payload.exe .text
move payload.exe64.bin ..\..\propagate\payload.bin
echo.
cl -DWINDOW -c -nologo -Os -O2 -Gm- -GR- -EHa -Oi -GS- payload.c
link /order:@extrabytes.txt /entry:WndProc /fixed payload.obj -subsystem:console -nodefaultlib -stack:0x100000,0x100000
xbin payload.exe .text
move payload.exe64.bin ..\..\extrabytes\payload.bin
echo.
cl -DSVCCTRL -c -nologo -Os -O2 -Gm- -GR- -EHa -Oi -GS- payload.c
link /order:@svcctrl.txt /entry:Handler /fixed payload.obj -subsystem:console -nodefaultlib -stack:0x100000,0x100000
xbin payload.exe .text
move payload.exe64.bin ..\..\svcctrl\payload.bin
echo.
cl -DALPC -c -nologo -Os -O2 -Gm- -GR- -EHa -Oi -GS- payload.c
link /order:@alpc.txt /entry:TpAlpcCallBack /fixed payload.obj -subsystem:console -nodefaultlib -stack:0x100000,0x100000
xbin payload.exe .text
copy payload.exe64.bin ..\..\alpc\payload.bin
move payload.exe64.bin ..\..\spooler\payload.bin
echo.
cl -DWORDBREAK -c -nologo -Os -O2 -Gm- -GR- -EHa -Oi -GS- payload.c
link /order:@wordwarping.txt /entry:Editwordbreakproca /fixed payload.obj -subsystem:console -nodefaultlib -stack:0x100000,0x100000
xbin payload.exe .text
move payload.exe64.bin ..\..\richedit\wordbreak.bin
echo.
cl -DHYPHENATE -c -nologo -Os -O2 -Gm- -GR- -EHa -Oi -GS- payload.c
link /order:@hyphentension.txt /entry:HyphenateProc /fixed payload.obj -subsystem:console -nodefaultlib -stack:0x100000,0x100000
xbin payload.exe .text
move payload.exe64.bin ..\..\richedit\hyphenate.bin
echo.
cl -DAUTOCORRECT -c -nologo -Os -O2 -Gm- -GR- -EHa -Oi -GS- payload.c
link /order:@autocourgette.txt /entry:Autocorrectproc /fixed payload.obj -subsystem:console -nodefaultlib -stack:0x100000,0x100000
xbin payload.exe .text
move payload.exe64.bin ..\..\richedit\autocorrect.bin
echo.
cl -DSTREAM -c -nologo -Os -O2 -Gm- -GR- -EHa -Oi -GS- payload.c
link /order:@streamception.txt /entry:Editstreamcallback /fixed payload.obj -subsystem:console -nodefaultlib -stack:0x100000,0x100000
xbin payload.exe .text
move payload.exe64.bin ..\..\richedit\stream.bin
echo.
cl -DCLIPBOARD -c -nologo -Os -O2 -Gm- -GR- -EHa -Oi -GS- payload.c
link /order:@clipboard.txt /entry:OleGetClipboardData /fixed payload.obj -subsystem:console -nodefaultlib -stack:0x100000,0x100000
xbin payload.exe .text
move payload.exe64.bin ..\..\richedit\clipboard.bin
echo.
cl -DLVCOMPARE -c -nologo -Os -O2 -Gm- -GR- -EHa -Oi -GS- payload.c
link /order:@listview.txt /entry:Pfnlvgroupcompare /fixed payload.obj -subsystem:console -nodefaultlib -stack:0x100000,0x100000
xbin payload.exe .text
move payload.exe64.bin ..\..\richedit\listview.bin
echo.
cl -DTVCOMPARE -c -nologo -Os -O2 -Gm- -GR- -EHa -Oi -GS- payload.c
link /order:@treeview.txt /entry:TvCompareFunc /fixed payload.obj -subsystem:console -nodefaultlib -stack:0x100000,0x100000
xbin payload.exe .text
move payload.exe64.bin ..\..\richedit\treeview.bin
echo.
cl -DRELEASE -c -nologo -Os -O2 -Gm- -GR- -EHa -Oi -GS- payload.c
link /order:@release.txt /entry:Release /fixed payload.obj -subsystem:console -nodefaultlib -stack:0x100000,0x100000
xbin payload.exe .text
move payload.exe64.bin ..\..\clipboard\release.bin
move payload.exe64.bin ..\..\tooltip\release.bin
echo.
cl -DWNF -c -nologo -Os -O2 -Gm- -GR- -EHa -Oi -GS- payload.c
link /order:@wnf.txt /entry:WnfCallback /fixed payload.obj -subsystem:console -nodefaultlib -stack:0x100000,0x100000
xbin payload.exe .text
move payload.exe64.bin ..\..\wnf\payload.bin
echo.
cl -DWINSOCK -c -nologo -Os -O2 -Gm- -GR- -EHa -Oi -GS- payload.c
link /order:@winsock.txt /entry:WSHGetSocketInformation /fixed payload.obj -subsystem:console -nodefaultlib -stack:0x100000,0x100000
xbin payload.exe .text
move payload.exe64.bin ..\..\wsh\payload.bin
echo.
cl -DDDE -c -nologo -Os -O2 -Gm- -GR- -EHa -Oi -GS- payload.c
link /order:@dde.txt /entry:DDECallback /fixed payload.obj -subsystem:console -nodefaultlib -stack:0x100000,0x100000
xbin payload.exe .text
move payload.exe64.bin ..\..\dde\payload.bin
echo.
cl -DQUERYINTERFACE -c -nologo -Os -O2 -Gm- -GR- -EHa -Oi -GS- payload.c
link /order:@queryinterface.txt /entry:QueryInterface /fixed payload.obj -subsystem:console -nodefaultlib -stack:0x100000,0x100000
xbin payload.exe .text
move payload.exe64.bin ..\..\tooltip\queryinterface.bin