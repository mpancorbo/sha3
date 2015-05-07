

; SHA-3 in x64 assembly
; Odzhan

ifdef __JWASM__
.x64
.model flat, C
endif

option prologue:none
option epilogue:none
option casemap:none

include sha3.inc

.code

; ***********************************************
;
; SHA3_Init (&ctx, int);
;
; ***********************************************
  public SHA3_Init
SHA3_Init proc
    ; save
    push   rax
    push   rcx
    push   rdx
    push   rdi
    ; --------
    mov    rdi, rcx        ; ctx

    ; memset (ctx, 0, sizeof SHA3_CTX);
    push   sizeof SHA3_CTX
    pop    rcx
    xor    eax, eax
    push   rdi
    rep    stosb
    pop    rdi
    
    mov    al, SHA3_224_CBLOCK
    mov    cl, SHA3_224_DIGEST_LENGTH
    dec    edx
    js     exit_init
    
    mov    al, SHA3_256_CBLOCK
    mov    cl, SHA3_256_DIGEST_LENGTH
    jz     exit_init
    
    mov    al, SHA3_384_CBLOCK
    mov    cl, SHA3_384_DIGEST_LENGTH
    dec    edx
    jz     exit_init
    
    mov    al, SHA3_512_CBLOCK
    mov    cl, SHA3_512_DIGEST_LENGTH
exit_init:
    mov    [rdi][SHA3_CTX.blklen ], rax
    mov    [rdi][SHA3_CTX.dgstlen], rcx
    mov    [rdi][SHA3_CTX.rounds ], SHA3_ROUNDS
    ; restore
    pop    rdi
    pop    rdx
    pop    rcx
    pop    rax
    ret
SHA3_Init endp

; ***********************************************
;
; SHA3_Update (SHA3_CTX*, void*, size_t);
;
; ***********************************************
  public SHA3_Update
SHA3_Update proc
    push   rax
    push   rbx
    push   rcx
    push   rdx
    push   rsi
    push   rdi
    ; -------------
    mov    rbx, rcx         ; ctx
    mov    rsi, rdx         ; input
    mov    rax, r8          ; len
    mov    edx, [rbx][SHA3_CTX.index]  ; idx
update_loop:
    ; r = MIN(len, ctx->buflen - idx);
    mov    rcx, [rbx][SHA3_CTX.blklen]
    sub    ecx, edx
    cmp    ecx, eax
    cmovae ecx, eax
    ; memcpy ((void*)&ctx->buf[idx], p, r);
    lea    rdi, [rbx][SHA3_CTX.blk][rdx]
    ; idx += r
    add    edx, ecx
    ; len -= r
    sub    eax, ecx
    rep    movsb
    ; if ((idx + r) < ctx->buflen) break;
    cmp    rdx, [rbx][SHA3_CTX.blklen]
    jb     save_index

    mov    rcx, rbx
    call   SHA3_Transform
    xor    edx, edx
    jmp    update_loop
save_index:  
    mov    [rbx][SHA3_CTX.index], edx
    ; -------
    pop    rdi
    pop    rsi
    pop    rdx
    pop    rcx
    pop    rbx
    pop    rax
    ret
SHA3_Update endp

; ***********************************************
;
; SHA3_Final (void*, SHA3_CTX*);
;
; ***********************************************
  public SHA3_Final
SHA3_Final proc
    push   rax
    push   rbx
    push   rcx
    push   rdx
    push   rsi
    push   rdi
    ; -------------
    mov    rbx, rcx   ; rbx = dgst
    mov    rsi, rdx   ; rsi = ctx

    lea    rdi, [rsi][SHA3_CTX.blk]
    mov    rcx, [rsi][SHA3_CTX.blklen]
    mov    eax, [rsi][SHA3_CTX.index]
    sub    ecx, eax
    add    rdi, rax
    xor    eax, eax
    rep    stosb
    
    mov    rdi, rbx
    mov    rcx, rdx
    
    lea    rax, [rsi][SHA3_CTX.blk   ]
    mov    ebx, [rsi][SHA3_CTX.index ]
    mov    rdx, [rsi][SHA3_CTX.blklen]
    
    mov    byte ptr[rax+rbx  ], 6
    or     byte ptr[rax+rdx-1], 80h

    call   SHA3_Transform
    
    mov    rcx, [rsi][SHA3_CTX.dgstlen]
    rep    movsb
    ; -------------
    pop    rdi
    pop    rsi
    pop    rdx
    pop    rcx
    pop    rbx
    pop    rax
    ret
SHA3_Final endp

r    equ <rbx>
i    equ <rdx> ; rcx is needed for rotations
j    equ <rbp>

t1   equ <r8>
t2   equ <r9>
rnds equ <r10d>

_st equ <rsi>
_bc equ <rdi>

; ***********************************************
;
; SHA3_Transform (SHA3_CTX*);
;
; ***********************************************
  public SHA3_Transform
SHA3_Transform proc
    push   rax
    push   rbx
    push   rcx
    push   rdx
    push   rdi
    push   rsi
    push   rbp
    push   r8
    push   r9
    push   r10
    
    ; set up workspace
    sub    rsp, 5*sizeof qword
    
    mov    rbx, rcx                ; ctx
    
    mov    rnds, [rbx][SHA3_CTX.rounds]

    ; for (i=0; i<ctx->buflen/8; i++) 
    ;   st[i] ^= p[i];
    lea    rdi, [rbx][SHA3_CTX.state ]
    lea    rsi, [rbx][SHA3_CTX.blk   ]
    mov    rcx, [rbx][SHA3_CTX.blklen]
    shr    ecx, 3    ; /= 8
xor_buf:
    lodsq
    xor    rax, [rdi]
    stosq
    loop   xor_buf

    lea    _st, [rbx][SHA3_CTX.state]
    mov    _bc, rsp
    
    ; ===========================================
    ; for (r=0; r<rnds; r++)
    xor    r, r
round_step:
    ; Theta
    ; for (i = 0; i < 5; i++)     
    ;   bc[i] = st[i + 0 ] ^ 
    ;           st[i + 5 ] ^ 
    ;           st[i + 10] ^ 
    ;           st[i + 15] ^ 
    ;           st[i + 20];
    ; ===========================================
    xor    i, i
theta_step1:
    mov    t1, [_st+8*i+20*8]
    xor    t1, [_st+8*i+15*8]
    xor    t1, [_st+8*i+10*8]
    xor    t1, [_st+8*i+ 5*8]
    xor    t1, [_st+8*i     ]
    mov    [_bc+8*i         ], t1
    inc    i
    cmp    i, 5
    jne    theta_step1
      
    ; for (i = 0; i < 5; i++) {
    ;   t = bc[(i + 4) % 5] ^ ROTL64(bc[(i + 1) % 5], 1);
    ;   for (j = 0; j < 25; j += 5)
    ;     st[j + i] ^= t;
    ; }
    ; *******************************************
    ; for (i = 0; i < 5; i++)
    ; ===========================================
    xor    i, i
theta_step2:
    ; t = ROTL64(bc[(i + 1) % 5], 1)
    movzx  t1, byte ptr keccakf_mod5[i+1]
    mov    t1, [_bc+8*t1]
    rol    t1, 1
    ; bc[(i + 4) % 5]
    movzx  t2, byte ptr keccakf_mod5[i+4]
    xor    t1, [_bc+8*t2]
    ; for (j = 0; j < 25; j += 5)
    ; ===========================================
    xor    j, j
theta_step3:
    ; st[j + i] ^= t;
    lea    t2, [j+i]
    xor    [_st+8*t2], t1
    
    add    j, 5
    cmp    j, 25
    jne    theta_step3
    
    inc    i
    cmp    i, 5
    jne    theta_step2
            
    ; // Rho Pi
    ; t = st[1];
    ; for (i = 0; i < 24; i++) {
    ;   j = keccakf_piln[i];
    ;   bc[0] = st[j];
    ;   st[j] = ROTL64(t, keccakf_rotc[i]);
    ;   t = bc[0];
    ; }
    ; *************************************
    ; t = st[1]
    mov    t1, [_st+8]
    ; ===========================================
    xor    i, i
rho_pi_step1:
    ; for (i = 0; i < 24; i++)
    ; j = keccakf_piln[i];
    movzx  j, byte ptr keccakf_piln[i]
    ; bc[0] = st[j];
    mov    t2, [_st+8*j]
    mov    [_bc], t2
    ; st[j] = ROTL64(t, keccakf_rotc[i]);
    movzx  ecx, byte ptr keccakf_rotc[i]
    rol    t1, cl
    mov    [_st+8*j], t1
    mov    t1, t2
    inc    i
    cmp    i, 24
    jne    rho_pi_step1
      
    ; // Chi
    ; for (j = 0; j < 25; j += 5) {
    ;   for (i = 0; i < 5; i++)
    ;     bc[i] = st[j + i];
    ;   for (i = 0; i < 5; i++)
    ;     st[j + i] ^= (~bc[(i+1)%5]) & bc[(i+2)%5];
    ; }
    ; *********************************
    ; for (j=0; j<25; j+=5)
    xor    j, j
chi_step1:
    ; for (i=0; i<5; i++)
    xor    i, i
chi_step2:
    ; bc[i] = st[j + i];
    lea    t1, [j+i]
    mov    t1, [_st+8*t1]
    mov    [_bc+8*i], t1
    inc    i
    cmp    i, 5
    jne    chi_step2
      
    ; for (i=0; i<5; i++)
    xor    i, i
chi_step3:
    ; st[j + i] ^= (~bc[(i+1)%5]) & bc[(i+2)%5];
    movzx  t1, byte ptr keccakf_mod5[i+1]
    mov    t1, [_bc+8*t1]
    not    t1
    movzx  t2, byte ptr keccakf_mod5[i+2]
    and    t1, [_bc+8*t2]
    
    lea    t2, [j+i]
    xor    [_st+8*t2], t1
    
    inc    i
    cmp    i, 5
    jne    chi_step3
    
    add    j, 5
    cmp    j, 25
    jne    chi_step1
           
    ; // Iota
    ; st[0] ^= keccakf_rndc[round];
    mov    t1, qword ptr keccakf_rndc[8*r]
    xor    qword ptr [_st], t1

    inc    r
    cmp    r, r10
    jne    round_step
    
cleanup:
    add    rsp, 5*sizeof qword
    
    pop    r10
    pop    r9
    pop    r8
    
    pop    rbp
    pop    rsi
    pop    rdi
    pop    rdx
    pop    rcx
    pop    rbx
    pop    rax
    
    ret
SHA3_Transform endp

keccakf_rotc label qword
  db 1,  3,  6,  10, 15, 21, 28, 36, 45, 55, 2,  14
  db 27, 41, 56, 8,  25, 43, 62, 18, 39, 61, 20, 44

keccakf_piln label qword
  db 10, 7,  11, 17, 18, 3, 5,  16, 8,  21, 24, 4 
  db 15, 23, 19, 13, 12, 2, 20, 14, 22, 9,  6,  1
  
keccakf_mod5 label qword
  db 0, 1, 2, 3, 4, 0, 1, 2, 3, 4

; these are generated using linear feedback shift register
keccakf_rndc label qword
  dq 00000000000000001h, 00000000000008082h, 0800000000000808ah
  dq 08000000080008000h, 0000000000000808bh, 00000000080000001h
  dq 08000000080008081h, 08000000000008009h, 0000000000000008ah
  dq 00000000000000088h, 00000000080008009h, 0000000008000000ah
  dq 0000000008000808bh, 0800000000000008bh, 08000000000008089h
  dq 08000000000008003h, 08000000000008002h, 08000000000000080h 
  dq 0000000000000800ah, 0800000008000000ah, 08000000080008081h
  dq 08000000000008080h, 00000000080000001h, 08000000080008008h
  
  end