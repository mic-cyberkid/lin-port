.code

PUBLIC InternalDoSyscall

InternalDoSyscall PROC
    ; Arguments:
    ; rcx: SSN
    ; rdx: a1
    ; r8:  a2
    ; r9:  a3
    ; [rsp+40]: a4
    ; [rsp+48]: a5
    ; [rsp+56]: a6
    ; [rsp+64]: a7
    ; [rsp+72]: a8
    ; [rsp+80]: a9
    ; [rsp+88]: a10
    ; [rsp+96]: a11

    mov r10, rdx ; a1
    mov rdx, r8  ; a2
    mov r8, r9   ; a3
    mov r9, [rsp+40] ; a4

    ; Shift stack arguments for the kernel
    ; Kernel expects 5th arg at [rsp+40], but currently it is at [rsp+48]
    ; Use r11 as temporary (volatile, destroyed by syscall anyway)
    mov r11, [rsp+48]
    mov [rsp+40], r11 ; a5
    mov r11, [rsp+56]
    mov [rsp+48], r11 ; a6
    mov r11, [rsp+64]
    mov [rsp+56], r11 ; a7
    mov r11, [rsp+72]
    mov [rsp+64], r11 ; a8
    mov r11, [rsp+80]
    mov [rsp+72], r11 ; a9
    mov r11, [rsp+88]
    mov [rsp+80], r11 ; a10
    mov r11, [rsp+96]
    mov [rsp+88], r11 ; a11

    mov eax, ecx ; Move SSN into EAX for syscall
    syscall
    ret
InternalDoSyscall ENDP

END
