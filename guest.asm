; SPDX-License-Identifier: GPL-2.0
; Copyright 2019 Amazon.com, Inc. or its affiliates.
;
; Author:
;   Julian Stecklina <jsteckli@amazon.de>

BITS 64
ORG 0

slack_off:
        inc rax
	pause
	loop slack_off

	; Use initialized data so our .bin file has the correct size
SECTION .data

ALIGN 4096
target0: times 4096 db 0
target1: times 4096 db 0
