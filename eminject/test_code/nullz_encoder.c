//
// A simple PoC for the blog post.
// 
// odzhan

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <inttypes.h>
#include <limits.h>

typedef uint8_t u8;
typedef uint32_t u32;

#define NULLZ_KEY  0x4D
#define NULLZ_FILE "nullz.bin"

#define NULLZ_DECODER_SIZE 30

// compatible with x86 and x86-64
char NULLZ_DECODER[] = {
  /* 0000 */ "\xeb\x17"             /* jmp   0x19            */
  /* 0002 */ "\x5e"                 /* pop   esi             */
  /* 0003 */ "\xad"                 /* lodsd                 */
#define NULLZ_LEN 5
  /* 0004 */ "\x35\x78\x56\x34\x12" /* xor   eax, 0x12345678 */
  /* 0009 */ "\x91"                 /* xchg  eax, ecx        */
  /* 000A */ "\x56"                 /* push  esi             */
  /* 000B */ "\x5f"                 /* pop   edi             */
  /* 000C */ "\x56"                 /* push  esi             */
  /* 000D */ "\xac"                 /* lodsb                 */
  /* 000E */ "\xfe\xc8"             /* dec   al              */
  /* 0010 */ "\x75\x03"             /* jne   0x15            */
  /* 0012 */ "\xac"                 /* lodsb                 */
  /* 0013 */ "\x34\x4d"             /* xor   al, 0x4d        */
  /* 0015 */ "\xaa"                 /* stosb                 */
  /* 0016 */ "\xe2\xf5"             /* loop  0xd             */
  /* 0018 */ "\xc3"                 /* ret                   */
  /* 0019 */ "\xe8\xe4\xff\xff\xff" /* call  2               */
};

// create an executable loader
static
void make_loader(size_t inlen, const char *outfile) {
    struct stat fs;
    FILE *in=NULL, *out=NULL;
    void *buf=NULL;
    u8 *ptr;
    u32 key, xlen, outlen;
    
    // read size of file
    if(stat(outfile, &fs) != 0) {perror(outfile); goto make_end;}
    if(fs.st_size == 0) {printf("%s is empty.\n", outfile); goto make_end;}
    
    // allocate memory for decoder + file
    outlen = fs.st_size + NULLZ_DECODER_SIZE + sizeof(int);
    buf = malloc(outlen);
    if(buf == NULL) {perror("malloc()"); goto make_end;}
    
    in = fopen(outfile, "rb");
    if(!in) {perror(outfile); goto make_end;}
    
    out = fopen(NULLZ_FILE, "wb");
    if(!out) {perror(NULLZ_FILE); goto make_end;}
   
    // find a key for the original length
    for(key = -1; key != 0; key--) {
      xlen = inlen ^ key;
      while(xlen) {
        if(!(xlen & 0xFF)) break;
        xlen >>= 8;
      }
      if(xlen == 0) break;
    }
    if(key == 0) {
      printf("unable to find key.\n");
      goto make_end;
    }
    
    // 1. copy decoder
    ptr = (u8*)buf;
    memcpy(ptr, NULLZ_DECODER, NULLZ_DECODER_SIZE);
    
    // 2. set the key to decrypt original length
    memcpy(&ptr[NULLZ_LEN], &key, sizeof(key));
    ptr += NULLZ_DECODER_SIZE;
    
    // 3. set the original length of code
    xlen = inlen ^ key;
    memcpy(ptr, &xlen, sizeof(xlen));
    ptr += sizeof(xlen);
    
    // 4. set the data to decode
    fread(ptr, 1, fs.st_size, in);
    
    // 5. save data to file
    fwrite(buf, 1, outlen, out);
    
    printf("Loader saved to %s\n", NULLZ_FILE);
make_end:
    if(buf)free(buf);
    if(out)fclose(out);
    if(in)fclose(in);
}

// encode a file to eliminate null bytes
static
void nullz_encode(FILE *in, FILE *out) {
    char c, t;
    
    for(;;) {
      // read byte
      c = getc(in);
      // end of file? exit
      if(feof(in)) break;
      // adding one is just an example
      t = c + 1;
      // is the result 0(avoid) or 1(escape)?
      if(t == 0 || t == 1) {
        // write escape sequence
        putc(0x01, out);
        // XOR is just an example. 
        // Avoid using 0x00 or 0xFF with XOR!
        putc(c ^ NULLZ_KEY, out);
      } else {
        // save byte plus 1
        putc(c + 1, out);
      }
    }
}

// decode a file to restore null bytes
static
void nullz_decode(FILE *in, FILE *out) {
    char c, t;
    
    for(;;) {
      // read byte
      c = getc(in);
      // end of file? exit
      if(feof(in)) break;
      // if this is an escape sequence
      if(c == 0x01) {
        // read next byte and XOR it
        c = getc(in);
        putc(c ^ NULLZ_KEY, out);
      } else {
        // else subtract byte
        putc(c - 1, out);
      }
    }
}

// User interface.  Args are input and output file.
int main(int argc, char **argv) {
    struct stat fs;
    FILE *in, *out;
    
    // Check arguments
    if ((argc!=4)||((argv[1][0]!='e')&&(argv[1][0]!='d'))) {
        printf("Usage: nullz e/d infile outfile\n");
        return 0;
    }
    if(stat(argv[2], &fs) != 0) {perror(argv[2]); return -1;}
    if(fs.st_size == 0) {printf("%s is empty.\n", argv[2]); return -1;}
    
    in = fopen(argv[2], "rb");
    if (!in) {perror(argv[2]); return -1;}
    
    out = fopen(argv[3], "wb");
    if (!out) {perror(argv[3]); return -1;}
    
    if (argv[1][0]=='e') {
        printf("Encoding %s to %s ...\n", argv[2], argv[3]);
        nullz_encode(in, out);
    } else {
        printf("Decoding %s from %s ...\n", argv[3], argv[2]);
        nullz_decode(in, out);
    }
    fclose(in);
    fclose(out);
    
    make_loader(fs.st_size, argv[3]);
    return 0;
}
