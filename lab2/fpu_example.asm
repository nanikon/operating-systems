global _start

section .text 
_start:
  fldpi			
  fld1
  fldln2
  start_die:
  test rax, rax
  jmp start_die
  ret
