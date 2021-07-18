@echo off
cl -nologo -Os xbin.cpp
echo CONSOLE
cl -DCONSOLE -c -nologo -Os -O2 -Gm- -GR- -EHa -Oi -GS- payload.c
link /order:@conhost.txt /entry:GetWindowHandle /fixed payload.obj -subsystem:console -nodefaultlib -stack:0x100000,0x100000
xbin payload.exe .text
move payload.exe64.bin ..\..\conhost\payload.bin
echo SUBCLASS
cl -DSUBCLASS -c -nologo -Os -O2 -Gm- -GR- -EHa -Oi -GS- payload.c
link /order:@propagate.txt /entry:SubclassProc /fixed payload.obj -subsystem:console -nodefaultlib -stack:0x100000,0x100000
xbin payload.exe .text
move payload.exe64.bin ..\..\propagate\payload.bin
echo WINDOW
cl -DWINDOW -c -nologo -Os -O2 -Gm- -GR- -EHa -Oi -GS- payload.c
link /order:@extrabytes.txt /entry:WndProc /fixed payload.obj -subsystem:console -nodefaultlib -stack:0x100000,0x100000
xbin payload.exe .text
move payload.exe64.bin ..\..\extrabytes\payload.bin
echo Service Control
cl -DSVCCTRL -c -nologo -Os -O2 -Gm- -GR- -EHa -Oi -GS- payload.c
link /order:@svcctrl.txt /entry:Handler /fixed payload.obj -subsystem:console -nodefaultlib -stack:0x100000,0x100000
xbin payload.exe .text
move payload.exe64.bin ..\..\svcctrl\payload.bin
echo ALPC
cl -DALPC -c -nologo -Os -O2 -Gm- -GR- -EHa -Oi -GS- payload.c
link /order:@alpc.txt /entry:TpAlpcCallBack /fixed payload.obj -subsystem:console -nodefaultlib -stack:0x100000,0x100000
xbin payload.exe .text
copy payload.exe64.bin ..\..\alpc\payload.bin
move payload.exe64.bin ..\..\spooler\payload.bin
echo WORDBREAK
cl -DWORDBREAK -c -nologo -Os -O2 -Gm- -GR- -EHa -Oi -GS- payload.c
link /order:@wordwarping.txt /entry:Editwordbreakproca /fixed payload.obj -subsystem:console -nodefaultlib -stack:0x100000,0x100000
xbin payload.exe .text
move payload.exe64.bin ..\..\richedit\wordbreak.bin
echo HYPHENATE
cl -DHYPHENATE -c -nologo -Os -O2 -Gm- -GR- -EHa -Oi -GS- payload.c
link /order:@hyphentension.txt /entry:HyphenateProc /fixed payload.obj -subsystem:console -nodefaultlib -stack:0x100000,0x100000
xbin payload.exe .text
move payload.exe64.bin ..\..\richedit\hyphenate.bin
echo AUTOCORRECT
cl -DAUTOCORRECT -c -nologo -Os -O2 -Gm- -GR- -EHa -Oi -GS- payload.c
link /order:@autocourgette.txt /entry:Autocorrectproc /fixed payload.obj -subsystem:console -nodefaultlib -stack:0x100000,0x100000
xbin payload.exe .text
move payload.exe64.bin ..\..\richedit\autocorrect.bin
echo STREAM
cl -DSTREAM -c -nologo -Os -O2 -Gm- -GR- -EHa -Oi -GS- payload.c
link /order:@streamception.txt /entry:Editstreamcallback /fixed payload.obj -subsystem:console -nodefaultlib -stack:0x100000,0x100000
xbin payload.exe .text
move payload.exe64.bin ..\..\richedit\stream.bin
echo CLIPBOARD
cl -DCLIPBOARD -c -nologo -Os -O2 -Gm- -GR- -EHa -Oi -GS- payload.c
link /order:@clipboard.txt /entry:OleGetClipboardData /fixed payload.obj -subsystem:console -nodefaultlib -stack:0x100000,0x100000
xbin payload.exe .text
move payload.exe64.bin ..\..\richedit\clipboard.bin
echo LVCOMPARE
cl -DLVCOMPARE -c -nologo -Os -O2 -Gm- -GR- -EHa -Oi -GS- payload.c
link /order:@listview.txt /entry:Pfnlvgroupcompare /fixed payload.obj -subsystem:console -nodefaultlib -stack:0x100000,0x100000
xbin payload.exe .text
move payload.exe64.bin ..\..\richedit\listview.bin
echo TVCOMPARE
cl -DTVCOMPARE -c -nologo -Os -O2 -Gm- -GR- -EHa -Oi -GS- payload.c
link /order:@treeview.txt /entry:TvCompareFunc /fixed payload.obj -subsystem:console -nodefaultlib -stack:0x100000,0x100000
xbin payload.exe .text
move payload.exe64.bin ..\..\richedit\treeview.bin
echo RELEASE
cl -DRELEASE -c -nologo -Os -O2 -Gm- -GR- -EHa -Oi -GS- payload.c
link /order:@release.txt /entry:Release /fixed payload.obj -subsystem:console -nodefaultlib -stack:0x100000,0x100000
xbin payload.exe .text
copy payload.exe64.bin ..\..\clipboard\release.bin
move payload.exe64.bin ..\..\tooltip\release.bin
echo WNF
cl -DWNF -c -nologo -Os -O2 -Gm- -GR- -EHa -Oi -GS- payload.c
link /order:@wnf.txt /entry:WnfCallback /fixed payload.obj -subsystem:console -nodefaultlib -stack:0x100000,0x100000
xbin payload.exe .text
move payload.exe64.bin ..\..\wnf\payload.bin
echo WINSOCK
cl -DWINSOCK -c -nologo -Os -O2 -Gm- -GR- -EHa -Oi -GS- payload.c
link /order:@winsock.txt /entry:WSHGetSocketInformation /fixed payload.obj -subsystem:console -nodefaultlib -stack:0x100000,0x100000
xbin payload.exe .text
move payload.exe64.bin ..\..\wsh\payload.bin
echo DDE
cl -DDDE -c -nologo -Os -O2 -Gm- -GR- -EHa -Oi -GS- payload.c
link /order:@dde.txt /entry:DDECallback /fixed payload.obj -subsystem:console -nodefaultlib -stack:0x100000,0x100000
xbin payload.exe .text
move payload.exe64.bin ..\..\dde\payload.bin
echo QUERYINTERFACE
cl -DQUERYINTERFACE -c -nologo -Os -O2 -Gm- -GR- -EHa -Oi -GS- payload.c
link /order:@queryinterface.txt /entry:QueryInterface /fixed payload.obj -subsystem:console -nodefaultlib -stack:0x100000,0x100000
xbin payload.exe .text
move payload.exe64.bin ..\..\tooltip\queryinterface.bin
echo CTRL
cl -DCTRL -c -nologo -Os -O2 -Gm- -GR- -EHa -Oi -GS- payload.c
link /order:@ctrl.txt /entry:HandlerRoutine /fixed payload.obj -subsystem:console -nodefaultlib -stack:0x100000,0x100000
xbin payload.exe .text
move payload.exe64.bin ..\..\ctrlinject\handler.bin
echo ETW
cl -DETW -c -nologo -Os -O2 -GS- payload.c
link /order:@etw.txt /entry:EtwEnableCallback /fixed payload.obj -subsystem:console -nodefaultlib -stack:0x100000,0x100000
xbin payload.exe .text
move payload.exe64.bin ..\..\etw\callback.bin