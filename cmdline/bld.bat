@echo off
yasm -fbin -DBIN winexec1.asm -owinexec1.bin
yasm -fwin64 winexec1.asm -owinexec1.obj
cl /MD var_inject.c winexec1.obj