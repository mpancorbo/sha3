

; SHA-3 in x86-64 assembly
; Odzhan

.x64
.model flat, C

r   equ <ebx>
i   equ <ecx>
j   equ <edx>
t   equ <mm0>
_st equ <rsi>
_bc equ <rdi>

SHA3_CTX struct
  state   dq 25 dup (?)
  index   dd ?
  dgstlen dd ?
  rounds  dd ?
  blklen  dd ?
  blk     db 256 dup (?)
SHA3_CTX ends

.code

  public sha3_transform
  public _sha3_transform
_sha3_transform:
sha3_transform proc ctx:dword
    local bc[5]:qword
    local rnds :dword
    
    pushad
    
    mov    ebx, ctx
    mov    eax, [ebx][SHA3_CTX.rounds]
    mov    rnds, eax
    lea    edi, [ebx][SHA3_CTX.state]
    lea    esi, [ebx][SHA3_CTX.blk]
    mov    ecx, [ebx][SHA3_CTX.blklen]
    shr    ecx, 3
xor_blk:
    lodsd
    xor    eax, [edi]
    stosd
    loop   xor_blk
    
    lea    eax, [ebx][SHA3_CTX.state]
    mov    _st, eax
    
    xor    r, r
    lea    _bc, bc
    
    .repeat
      ; Theta
      ; for (i = 0; i < 5; i++)     
      ;   bc[i] = st[i + 0 ] ^ 
      ;           st[i + 5 ] ^ 
      ;           st[i + 10] ^ 
      ;           st[i + 15] ^ 
      ;           st[i + 20]; 
      xor    i, i
      .repeat
        mov    t, [_st+8*i+20*8]
        xor    t, [_st+8*i+15*8]
        xor    t, [_st+8*i+10*8]
        xor    t, [_st+8*i+5*8]
        xor    t, [_st+8*i]
        mov    [_bc+8*i], t
        inc    i
        cmp    i, 5
      .until zero?
      
      ; for (i = 0; i < 5; i++) {
      ;   t = bc[(i + 4) % 5] ^ ROTL64(bc[(i+1)%5], 1);
      ;   for (j = 0; j < 25; j += 5)
      ;     st[j + i] ^= t;
      ; }
      ; ************************************
      ; for (i=0; i<5; i++)
      xor    i, i
      .repeat
        ; t = ROTL64(bc[(i+1)%5], 1)
        movzx  eax, byte ptr keccakf_mod5[i+1]
        mov    t, [_bc+8*eax]
        rol    t, 1
        ; bc[(i+4)%5]
        mov    al, byte ptr keccakf_mod5[i+4]
        xor    t, [_bc+8*eax]
        ; for (j=0; j<25; j+=5)
        xor    j, j
        .repeat
          ; st[j+i] ^= t;
          lea    eax, [j+i]
          xor    [_st+8*eax], t
          add    j, 5
          cmp    j, 25
        .until zero?
        inc    i
        cmp    i, 5
      .until zero?
            
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
      xor    i, i
      ; for (i = 0; i < 24; i++)
      .repeat
        ; j = keccakf_piln[i];
        movzx  j, byte ptr keccakf_piln[i]
        ; bc[0] = st[j];
        ; st[j] = ROTL64(t, keccakf_rotc[i]);
        ; t = bc[0];
        movzx  ecx, byte ptr keccakf_rotc[i]
        rol    t, cl
        xchg   [_st+8*j], t
        mov    [_bc], t
        inc    i
        cmp    i, 24
      .until zero?
      
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
      .repeat
        ; for (i=0; i<5; i++)
        xor    i, i
        .repeat
          ; bc[i] = st[j + i];
          lea    eax, [j+i]
          mov    t, [_st+8*eax]
          mov    [_bc+8*i], t
          inc    i
          cmp    i, 5
        .until zero?
        
        ; for (i=0; i<5; i++)
        xor    i, i
        .repeat
          ; st[j + i] ^= (~bc[(i+1)%5]) & bc[(i+2)%5];
          movzx  eax, byte ptr keccakf_mod5[i+1]
          mov    t, [_bc+8*eax]
          not    t
          mov    al, byte ptr keccakf_mod5[i+2]
          and    t, [_bc+8*eax]
          lea    eax, [j+i]
          xor    [_st+8*eax], t
          inc    i
          cmp    i, 5
        .until zero?
        add    j, 5
        cmp    j, 25
      .until zero?
           
      ; // Iota
      ; st[0] ^= keccakf_rndc[round];
      mov     t, keccakf_rndc[8*r]
      xor     [_st], t    
      inc  r
    .until r == rnds
    popad
    ret
sha3_transform endp

keccakf_rotc label dword
  db 1,  3,  6,  10, 15, 21, 28, 36, 45, 55, 2,  14
  db 27, 41, 56, 8,  25, 43, 62, 18, 39, 61, 20, 44

keccakf_piln label dword
  db 10, 7,  11, 17, 18, 3, 5,  16, 8,  21, 24, 4 
  db 15, 23, 19, 13, 12, 2, 20, 14, 22, 9,  6,  1
  
keccakf_mod5 label dword
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