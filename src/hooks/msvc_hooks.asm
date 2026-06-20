EXTERN penter_handler:PROC ;
EXTERN pexit_handler:PROC ;

_TEXT SEGMENT

PUBLIC _penter
_penter PROC
    ; Saving volatile GP registers
    push rax
    push rcx
    push rdx
    push r8
    push r9
    push r10
    push r11
    pushfq

    ;aligning stack at 16bytes before the call
    ;pushed 7regs(8 bytes each) +pushfq = 64bytes plus the original return address already on the stack =72 bytes   

    sub rsp, 8
    sub rsp, 32
    call penter_handler 

    add rsp, 40

    popfq
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdx
    pop rcx
    pop rax

    ret 
_penter ENDP


PUBLIC _pexit
_pexit PROC 
    push rax
    push rcx
    push rdx
    push r8
    push r9
    push r10
    push r11
    pushfq

    sub rsp, 9
    sub rsp, 32
    call pexit_handler

    add rsp, 40

    popfq
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdx
    pop rcx
    pop rax

    ret
_pexit ENDP


_TEXT ENDS
END