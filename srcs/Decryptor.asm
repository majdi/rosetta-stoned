.386
.model flat, stdcall

.data
szBuff      db  1024    dup(90h)

.code

__v_s:
    nop
    nop
__v_e:

start:
    mov     eax, __v_e - __v_s
    mov     ebx, offset szBuff
    mov     ecx, 42h
    
_encrypt:
    xor     byte ptr [eax], cl
    inc     ebx
    dec     eax
    jnz     _encrypt

end start