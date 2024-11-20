;; Credit: Adapted from https://github.com/Cracked5pider/Stardust

[BITS 64]

DEFAULT REL

EXTERN InitializeHannibal

GLOBAL Start
GLOBAL StRipStart
GLOBAL StRipEnd

GLOBAL ___chkstk_ms

[SECTION .text$STUB]
    
    ;; 16-byte stack alignment
    Start:
        push  rsi
        mov   rsi, rsp
        and   rsp, 0FFFFFFFFFFFFFFF0h
        sub   rsp, 020h
        call  InitializeHannibal
        mov   rsp, rsi
        pop   rsi
        ret

    StRipStart:
        call StRipPtrStart
        ret

    StRipPtrStart:
        mov	rax, [rsp] ;; get the return address
        sub rax, 0x1b  ;; subtract the instructions size to get the base address
        ret            ;; return to StRipStart

    ;; If not in this section it points to a bunch of zeros and crashes.
    ;; Also works in .text$CODE section. 
    ;; https://www.metricpanda.com/rival-fortress-update-45-dealing-with-__chkstk-__chkstk_ms-when-cross-compiling-for-windows/
    ;; https://nullprogram.com/blog/2024/02/05/
    ;; https://skanthak.hier-im-netz.de/msvcrt.html
    ___chkstk_ms:
        ret


[SECTION .text$E]

    StRipEnd:
        call StRetPtrEnd
        ret

    StRetPtrEnd:
        mov rax, [rsp] ;; get the return address
        add	rax, 0xb   ;; get implant end address
        ret            ;; return to StRipEnd
    

[SECTION .text$P]
   
    SymHannibalEnd:
        db 'H', 'A', 'N', 'N', 'I', 'B', 'A', 'L', '-', 'E', 'N', 'D'