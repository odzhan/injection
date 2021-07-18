
#include "lde.h"

int 
main(int argc, char *argv[]) {
    LDE *lde;
    
    if(argc != 2) {
      printf("usage: dis <system call name>\n");
      return 0;
    }
    
    // create length disassembly engine
    lde = new LDE();
      
    lde->DisassembleSyscall(argv[1]);

    delete lde;
    
    return 0;
}