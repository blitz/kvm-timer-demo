## Overview

This is a proof-of-concept self-contained L1TF demonstrator that works in the
presence of the Linux kernel's default L1TF mitigation. This code does by design
not work on a vanilla Linux kernel. The purpose is to help validate and improve
defenses and not build a practical attack.

The Linux Kernel User's and Administrator's Guide describes two attack scenarios
for L1TF. The first is a malicious userspace application that uses L1TF to leak
data via left-over (but disabled) page table entries in the kernel
(CVE-2018-3620). The second is a malicious guest that controls its own page
table to leak arbitrary data from the L1 cache (CVE-2018-3646).

The demo combines both approaches. It is a malicious userspace application that
creates an ad-hoc virtual machine to leak memory.

It works by starting a cache loading thread that can be directed to prefetch
arbitrary memory by triggering a "cache load gadget". This is any code in the
kernel that accesses user controlled memory under speculation. For the purpose
of this demonstration, we've included a patch to Linux to add such a gadget.
Another thread is executing a tiny bit of assembly in guest mode to perform the
actual L1TF attack. These threads are pinned to a hyperthread pair to make them
share the L1 cache.

See also https://xenbits.xen.org/xsa/advisory-289.html for more context.

## Build Requirements

- nasm
- xxd
- g++ >= 4.8.1
- make

## Execution Requirements

- access to /dev/kvm
- running kernel patched with 0001-XXX-Add-proof-of-concept-cache-load-gadget-in-mincor.patch
- a vulnerable CPU that supports Intel TSX and Hyperthreading

## Build

```
make
```

## Running

To dump 1024 bytes of physical memory starting at 0xd0000, use the following call:

./l1tf 0xffff888000000000 0xd0000 $(./ht-siblings.sh | head -n 1) 1024 > memory.dump

The memory dump can be inspected via hexdump. The first parameter of the l1tf
binary is the start of the linear mapping of all physical memory in the kernel.
This is always 0xffff888000000000 for kernels without KASLR enabled.

The code has been tested on Broadwell laptop and Kaby Lake desktop parts, other
systems may require tweaking of MAX_CACHE_LATENCY in guest.asm.

If the L1TF mechanism is not working, the tool typically returns all zeroes.

## References

[1] https://www.kernel.org/doc/html/latest/admin-guide/l1tf.html#default-mitigations
