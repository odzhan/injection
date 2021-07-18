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

#define CP1252_KEY 0x4d

typedef uint8_t u8;
typedef uint32_t u32;

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

// encode raw data to CP-1252 compatible data
static
void cp1252_encode(FILE *in, FILE *out) {
    uint8_t c, t;
    
    for(;;) {
      // read byte
      c = getc(in);
      // end of file? exit
      if(feof(in)) break;
      // if the result of c + 1 is disallowed
      if(!is_decoder_allowed(c + 1)) {
        // write escape code
        putc(0x01, out);
        // save byte XOR'd with the 8-Bit key
        putc(c ^ CP1252_KEY, out);
      } else {
        // save byte plus 1
        putc(c + 1, out);
      }
    }
}

// decode data processed with cp1252_encode to their original values
static
void cp1252_decode(FILE *in, FILE *out) {
    uint8_t c, t;
    
    for(;;) {
      // read byte
      c = getc(in);
      // end of file? exit
      if(feof(in)) break;
      // if this is an escape code
      if(c == 0x01) {
        // read next byte
        c = getc(in);
        // XOR the 8-Bit key
        putc(c ^ CP1252_KEY, out);
      } else {
        // save byte minus one
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
        printf("Usage: cp1252 e/d infile outfile\n");
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
        cp1252_encode(in, out);
    } else {
        printf("Decoding %s from %s ...\n", argv[3], argv[2]);
        cp1252_decode(in, out);
    }
    fclose(in);
    fclose(out);
    return 0;
}
