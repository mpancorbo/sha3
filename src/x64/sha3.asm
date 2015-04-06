

; SHA-3 in x86/MMX assembly
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
    push   rdi
    push   rbx
    ; memset (ctx, 0, sizeof SHA3_CTX);
    push   rcx
    pop    rdi
    push   rcx
    pop    rbx
    push   sizeof SHA3_CTX
    pop    rcx
    xor    eax, eax
    rep    stosb

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
    mov    [rbx][SHA3_CTX.blklen ], eax
    mov    [rbx][SHA3_CTX.dgstlen], ecx
    mov    [rbx][SHA3_CTX.rounds ], SHA3_ROUNDS
    ; restore
    pop    rbx
    pop    rdi
    ret
SHA3_Init endp

; ***********************************************
;
; SHA3_Update (SHA3_CTX*, void*, size_t);
;
; ***********************************************
  public SHA3_Update
SHA3_Update proc
    push   rsi
    push   rdi
    push   rbx
    ; -------------
    mov    rbx, rcx
    mov    rsi, rdx
    mov    edx, [rbx][SHA3_CTX.index]  ; idx
    mov    rax, r8
    
update_loop:
    ; r = MIN(len, ctx->blklen - idx);
    mov    ecx, [rbx][SHA3_CTX.blklen]
    sub    ecx, edx
    cmp    ecx, eax
    cmovae ecx, eax
    ; memcpy ((void*)&ctx->blk[idx], p, r);
    lea    rdi, [rbx][SHA3_CTX.blk][rdx]
    ; idx += r
    add    edx, ecx
    ; len -= r
    sub    eax, ecx
    rep    movsb
    ; if ((idx + r) < ctx->blklen) break;
    cmp    edx, [rbx][SHA3_CTX.blklen]
    jb     save_index

    mov    rcx, rbx
    call   SHA3_Transform
    cdq
    jmp    update_loop
save_index:  
    mov    [rbx][SHA3_CTX.index], edx
    ; --------
    pop    rbx
    pop    rdi
    pop    rsi
    ret
SHA3_Update endp

; ***********************************************
;
; SHA3_Final (void*, SHA3_CTX*);
;
; ***********************************************
  public SHA3_Final
SHA3_Final proc
    push   rdi
    push   rsi
    push   rbx
    ; --------
    mov    rdi, rcx   ; rdi = output
    mov    rcx, rdx   ; rcx = ctx
    mov    rsi, rdx   ; rsi = state
    
    lea    rdx, [rcx][SHA3_CTX.blk]
    mov    ebx, [rcx][SHA3_CTX.index]
    mov    eax, [rcx][SHA3_CTX.blklen]
    mov    byte ptr[rdx+rbx  ], 6
    or     byte ptr[rdx+rax-1], 80h
    
    call   SHA3_Transform
    
    mov    ecx, [rcx][SHA3_CTX.dgstlen]
    rep    movsb
    ; --------
    pop    rbx
    pop    rsi
    pop    rdi
    ret
SHA3_Final endp

r    equ <rbx>
i    equ <rdx> ; rcx is needed for rotations
j    equ <rbp>
t    equ <r8>
x    equ <r9>
rnds equ <r10d>

_st equ <rsi>
_bc equ <rdi>

SHA3_WS struct
  bc   qword 5 dup (?)
SHA3_WS ends

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
    push   rsi
    push   rdi
    push   rbp
    
    ; set up workspace
    sub    rsp, sizeof SHA3_WS
    
    mov    rbx, rcx                ; ctx
    
    mov    rnds, [rbx][SHA3_CTX.rounds]

    ; for (i=0; i<ctx->blklen/8; i++) st[i] ^= p[i];
    lea    rdi, [rbx][SHA3_CTX.state]
    lea    rsi, [rbx][SHA3_CTX.blk]
    mov    ecx, [rbx][SHA3_CTX.blklen]
    shr    ecx, 3    ; /= 8
    cdq
xor_blk:
    lodsq
    xor    rax, [rdi]
    stosq
    mov    [rsi-8], rdx   ; zero buffer
    loop   xor_blk
    
    lea    _st, [rbx][SHA3_CTX.state]
    lea    _bc, [rsp][SHA3_WS.bc]
    
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
    mov    t, [_st+8*i+20*8]
    xor    t, [_st+8*i+15*8]
    xor    t, [_st+8*i+10*8]
    xor    t, [_st+8*i+5*8]
    xor    t, [_st+8*i]
    mov    [_bc+8*i], t
    inc    i
    cmp    i, 5
    jne    theta_step1
      
    ; for (i = 0; i < 5; i++) {
    ;   t = bc[(i + 4) % 5] ^ ROTL64(bc[(i+1)%5], 1);
    ;   for (j = 0; j < 25; j += 5)
    ;     st[j + i] ^= t;
    ; }
    ; ************************************
    ; for (i = 0; i < 5; i++)
    ; ===========================================
    xor    i, i
theta_step2:
    ; t = ROTL64(bc[(i + 1) % 5], 1)
    movzx  t, byte ptr keccakf_mod5[i+1]
    mov    t, [_bc+8*t]
    rol    t, 1
    ; bc[(i + 4) % 5]
    movzx  t, byte ptr keccakf_mod5[i+4]
    xor    t, [_bc+8*rax]
    ; for (j = 0; j < 25; j += 5)
    ; ===========================================
    xor    j, j
theta_step3:
    ; st[j + i] ^= t;
    lea    eax, [j+i]
    xor    [_st+8*rax], t
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
    mov    t, [_st+8]
    ; ===========================================
    xor    i, i
rho_pi_step1:
    ; for (i = 0; i < 24; i++)
    ; j = keccakf_piln[i];
    movzx  j, byte ptr keccakf_piln[i]
    ; bc[0] = st[j];
    mov    x, [_st+8*j]
    mov    [_bc], x
    ; st[j] = ROTL64(t, keccakf_rotc[i]);
    movzx  ecx, byte ptr keccakf_rotc[i]
    rol    t, cl
    mov    [_st+8*j], t
    mov    t, rax
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
    lea    x, [j+i]
    mov    t, [_st+8*x]
    mov    [_bc+8*i], t
    inc    i
    cmp    i, 5
    jne    chi_step2
      
    ; for (i=0; i<5; i++)
    xor    i, i
chi_step3:
    ; st[j + i] ^= (~bc[(i+1)%5]) & bc[(i+2)%5];
    movzx  x, byte ptr keccakf_mod5[i+1]
    mov    t, [_bc+8*x]
    movzx  x, byte ptr keccakf_mod5[i+2]
    not    qword ptr[_bc+8*x]
    and    t, [_bc+8*x]
    lea    x, [j+i]
    xor    [_st+8*x], t
    
    inc    i
    cmp    i, 5
    jne    chi_step3
    
    add    j, 5
    cmp    j, 25
    jne    chi_step1
           
    ; // Iota
    ; st[0] ^= keccakf_rndc[round];
    mov    t, qword ptr keccakf_rndc[8*r]
    xor    [_st], t

    inc    r
    cmp    r, r10
    jne    round_step
    
    add    rsp, sizeof SHA3_WS
    
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