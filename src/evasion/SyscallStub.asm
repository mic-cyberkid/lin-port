.code

PUBLIC InternalDoSyscall

InternalDoSyscall PROC
    mov eax, ecx ; SSN into EAX
    mov r10, rdx ; First param into r10
    
    ; Shift args
    mov rdx, r8  ; arg2
    mov r8, r9   ; arg3
    mov r9, [rsp+40] ; arg4

    ; Shift stack arguments for the kernel
    ; Kernel expects 5th arg at [rsp+40], but currently it is at [rsp+48]
    ; We have already moved arg4 to r9, so we can use [rsp+40]
    mov rax, [rsp+48]
    mov [rsp+40], rax ; arg5
    mov rax, [rsp+56]
    mov [rsp+48], rax ; arg6
    mov rax, [rsp+64]
    mov [rsp+56], rax ; arg7
    mov rax, [rsp+72]
    mov [rsp+64], rax ; arg8
    mov rax, [rsp+80]
    mov [rsp+72], rax ; arg9
    mov rax, [rsp+88]
    mov [rsp+80], rax ; arg10
    mov rax, [rsp+96]
    mov [rsp+88], rax ; arg11
    
    syscall
    ret
InternalDoSyscall ENDP

END
