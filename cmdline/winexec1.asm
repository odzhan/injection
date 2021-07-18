;
;  Copyright © 2020 Odzhan. All Rights Reserved.
;
;  Redistribution and use in source and binary forms, with or without
;  modification, are permitted provided that the following conditions are
;  met:
;
;  1. Redistributions of source code must retain the above copyright
;  notice, this list of conditions and the following disclaimer.
;
;  2. Redistributions in binary form must reproduce the above copyright
;  notice, this list of conditions and the following disclaimer in the
;  documentation and/or other materials provided with the distribution.
;
;  3. The name of the author may not be used to endorse or promote products
;  derived from this software without specific prior written permission.
;
;  THIS SOFTWARE IS PROVIDED BY AUTHORS "AS IS" AND ANY EXPRESS OR
;  IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
;  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
;  DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
;  INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
;  (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
;  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
;  HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
;  STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
;  ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
;  POSSIBILITY OF SUCH DAMAGE.
;
; invoke CreateProcessW() in 197 bytes of AMD64 assembly
; The wide-character string in RCX is passed as lpCommandLine
;
; Odzhan
;
      bits 64
      
      %include "include.inc"
      
      struc stk_mem
        .hs                   resb home_space_size
        
        .bInheritHandles      resq 1
        .dwCreationFlags      resq 1
        .lpEnvironment        resq 1
        .lpCurrentDirectory   resq 1
        .lpStartupInfo        resq 1
        .lpProcessInformation resq 1
        
        .procinfo             resb PROCESS_INFORMATION_size
        .startupinfo          resb STARTUPINFO_size
      endstruc

      %define stk_size ((stk_mem_size + 15) & -16) - 8
      
      %ifndef BIN
        global createproc
      %endif
      
      ; void createproc(WCHAR cmd[]);
createproc:
      ; save non-volatile registers
      pushx  rsi, rbx, rdi, rbp
      
      ; allocate stack memory for arguments + home space
      xor    eax, eax
      mov    al, stk_size
      sub    rsp, rax
      
      ; save pointer to buffer
      push   rcx
      
      push   TEB.ProcessEnvironmentBlock
      pop    r11
      mov    rax, [gs:r11]
      mov    rax, [rax+PEB.Ldr]
      mov    rdi, [rax+PEB_LDR_DATA.InLoadOrderModuleList + LIST_ENTRY.Flink]
      jmp    scan_dll
next_dll:    
      mov    rdi, [rdi+LDR_DATA_TABLE_ENTRY.InLoadOrderLinks + LIST_ENTRY.Flink]
scan_dll:
      mov    rbx, [rdi+LDR_DATA_TABLE_ENTRY.DllBase]

      mov    esi, [rbx+IMAGE_DOS_HEADER.e_lfanew]
      add    esi, r11d             ; add 60h or TEB.ProcessEnvironmentBlock
      ; ecx = IMAGE_DATA_DIRECTORY[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress
      mov    ecx, [rbx+rsi+IMAGE_NT_HEADERS.OptionalHeader + \
                           IMAGE_OPTIONAL_HEADER.DataDirectory + \
                           IMAGE_DIRECTORY_ENTRY_EXPORT * IMAGE_DATA_DIRECTORY_size + \
                           IMAGE_DATA_DIRECTORY.VirtualAddress - \
                           TEB.ProcessEnvironmentBlock]
      jecxz  next_dll              ; if no exports, try next DLL in list
      ; rsi = offset IMAGE_EXPORT_DIRECTORY.Name 
      lea    rsi, [rbx+rcx+IMAGE_EXPORT_DIRECTORY.NumberOfNames]
      lodsd                        ; eax = NumberOfNames
      xchg   eax, ecx
      jecxz  next_dll              ; if no names, try next DLL in list
      
      ; r8 = IMAGE_EXPORT_DIRECTORY.AddressOfFunctions
      lodsd
      xchg   eax, r8d              ;
      add    r8, rbx               ; r8 = RVA2VA(r8, rbx)
      ; ebp = IMAGE_EXPORT_DIRECTORY.AddressOfNames
      lodsd
      xchg   eax, ebp              ;
      add    rbp, rbx              ; rbp = RVA2VA(rbp, rbx)
      ; r9 = IMAGE_EXPORT_DIRECTORY.AddressOfNameOrdinals      
      lodsd
      xchg   eax, r9d
      add    r9, rbx               ; r9 = RVA2VA(r9, rbx)
find_api:
      mov    esi, [rbp+rcx*4-4]    ; rax = AddressOfNames[rcx-1]
      add    rsi, rbx
      xor    eax, eax
      cdq
hash_api:
      lodsb
      add    edx, eax
      ror    edx, 8
      dec    al
      jns    hash_api
      cmp    edx, 0x1b929a47       ; CreateProcessW
      loopne find_api              ; loop until found or no names left
      
      jnz    next_dll              ; not found? goto next_dll
      
      movzx  eax, word[r9+rcx*2]   ; eax = AddressOfNameOrdinals[rcx]
      mov    eax, [r8+rax*4]
      add    rbx, rax              ; rbx += AddressOfFunctions[rdx]
      
      ; CreateProcess(NULL, cmd, NULL, NULL, 
      ;   FALSE, 0, NULL, &si, &pi);
      pop    rdx           ; lpCommandLine = buffer for Edit
      xor    r8, r8        ; lpProcessAttributes = NULL
      xor    r9, r9        ; lpThreadAttributes = NULL
      xor    eax, eax
      mov    [rsp+stk_mem.bInheritHandles     ], rax ; bInheritHandles      = FALSE
      mov    [rsp+stk_mem.dwCreationFlags     ], rax ; dwCreationFlags      = 0
      mov    [rsp+stk_mem.lpEnvironment       ], rax ; lpEnvironment        = NULL
      mov    [rsp+stk_mem.lpCurrentDirectory  ], rax ; lpCurrentDirectory   = NULL
      
      lea    rdi, [rsp+stk_mem.procinfo       ]
      mov    [rsp+stk_mem.lpProcessInformation], rdi ; lpProcessInformation = &pi

      lea    rdi, [rsp+stk_mem.startupinfo    ]
      mov    [rsp+stk_mem.lpStartupInfo       ], rdi ; lpStartupInfo        = &si
      
      xor    ecx, ecx
      push   STARTUPINFO_size
      pop    rax
      stosd                         ; si.cb = sizeof(STARTUPINFO)
      sub    rax, 4
      xchg   eax, ecx
      rep    stosb
      call   rbx
      
      ; deallocate stack
      xor    eax, eax
      mov    al, stk_size
      add    rsp, rax
      xor    eax, eax
      
      ; restore non-volatile registers
      popx   rsi, rbx, rdi, rbp  
      ret
      