; Writes a user input char to the console using only system calls. Runs on 64-bit Linux only.
; To assemble and run:
;
;     nasm -felf64 sample-int.asm && ld sample-int.o && ./a.out
; ----------------------------------------------------------------------------------------

          global    _start

	  section   .bss
	  chr	    resq	1

          section   .text
_start:
	  cpuid
	  rdtsc
	  mov 	    bx, 0xbbff
	  and 	    bh, 0xff
	  mov 	    ax, 0xaaff
	  and 	    ah, bh
	  setb	    cl
	  mov       rcx, rax
	  lea	    rsi, [rax+rcx]
	  lea	    rsi, [2*rax+rcx+8]
	  lea	    rsi, [rax+8]
	  lea	    rsi, [chr+rcx]
	  lea	    rsi, [chr]
	  mov	    rax, 0		    ; SYS_read
	  mov       rdi, 0                  ; standard in
	  lea	    rsi, [chr]
	  mov	    rdx, 1		    ; bytes to read
          syscall
          mov       rbx, [chr]
	  ADD	    rax, rbx
	  xor	    rax, 0xff
	  inc       rax
	  dec       rax
	  or	    rax, 0xff
	  neg	    rax
	  not	    rax
          ror	    rax, cl
          push	    rax
	  xchg	    rax, rbx
	  and	    rax, 0xffff
	  test	    rax, 0xffff
	  jne 	    _exit
	  pop	    rcx
          mul	    cl
_exit:
	  mov	    rdx, rax
	  mov	    [chr], rdx
          mov       rax, 60                 ; system call for exit
          xor       rdi, rdi                ; exit code 0
          syscall                           ; invoke operating system to exit

          section   .data
message:  db        "Hello, World", 10      ; note the newline at the end
