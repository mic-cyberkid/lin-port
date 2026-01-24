.code

PUBLIC InternalDoSyscall

InternalDoSyscall PROC
    mov eax, ecx ; SSN into EAX
    mov r10, rdx ; First param into r10
    
    ; Shift args
    mov rdx, r8
    mov r8, r9
    mov r9, [rsp+40]
    
    syscall
    ret
InternalDoSyscall ENDP

END
