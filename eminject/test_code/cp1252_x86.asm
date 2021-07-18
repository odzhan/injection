
; cp1252 decoder in 40 bytes of x86/amd64 assembly
; presumes to be executing in RWX memory
; needs stack allocation if executing from RX memory
;
; odzhan

    bits 32
    
    %define CP1252_KEY 0x4D
    
    jmp    init_decode       ; read the program counter
    
    ; esi = source
    ; edi = destination 
    ; ecx = length
decode_bytes:
    lodsb                    ; read a byte
    dec    al                ; c - 1
    jnz    save_byte
    lodsb                    ; skip null byte
    lodsb                    ; read next byte
    xor    al, CP1252_KEY    ; c ^= CP1252_KEY
save_byte:
    stosb                    ; save in buffer
    lodsb                    ; skip null byte
    loop   decode_bytes
    ret
load_data:
    pop    esi               ; esi = start of data
    ; ********************** ; decode the 32-bit length
read_len:
    push   0                 ; len = 0
    push   esp               ; 
    pop    edi               ; edi = &len
    push   4                 ; 32-bits
    pop    ecx
    call   decode_bytes
    pop    ecx               ; ecx = len
    
    ; ********************** ; decode remainder of data
    push   esi               ; 
    pop    edi               ; edi = encoded data
    push   esi               ; save address for RET
    jmp    decode_bytes
init_decode:
    call   load_data
    ; CP1252 encoded data goes here..
    