.code

PUBLIC InternalDoSyscall

InternalDoSyscall PROC
    ; Arguments (x64 Windows Calling Convention):
    ; rcx: SSN (DWORD)
    ; rdx: gadget (PVOID)
    ; r8:  a1
    ; r9:  a2
    ; [rsp+40]: a3
    ; [rsp+48]: a4
    ; [rsp+56]: a5
    ; [rsp+64]: a6
    ; [rsp+72]: a7
    ; [rsp+80]: a8
    ; [rsp+88]: a9
    ; [rsp+96]: a10
    ; [rsp+104]: a11

    mov eax, ecx     ; eax = SSN
    mov r11, rdx     ; r11 = gadget address

    ; Start mapping arguments to kernel-expected registers/stack
    mov r10, r8      ; r10 = a1
    mov rdx, r9      ; rdx = a2
    mov r8, [rsp+40] ; r8 = a3
    mov r9, [rsp+48] ; r9 = a4

    ; Shift remaining stack arguments (a5-a11)
    ; Kernel expects a5 at [rsp+40]
    ; Currently a5 is at [rsp+56]

    mov rax, [rsp+56]
    mov [rsp+40], rax ; a5

    mov rax, [rsp+64]
    mov [rsp+48], rax ; a6

    mov rax, [rsp+72]
    mov [rsp+56], rax ; a7

    mov rax, [rsp+80]
    mov [rsp+64], rax ; a8

    mov rax, [rsp+88]
    mov [rsp+72], rax ; a9

    mov rax, [rsp+96]
    mov [rsp+80], rax ; a10

    mov rax, [rsp+104]
    mov [rsp+88], rax ; a11

    ; Restore ssn to eax
    mov eax, ecx

    ; Jump to gadget
    jmp r11
    ret
InternalDoSyscall ENDP

END
