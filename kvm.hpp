// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright 2019 Amazon.com, Inc. or its affiliates.
 *
 * Author:
 *   Julian Stecklina <jsteckli@amazon.de>
 *
 */

#pragma once

#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <linux/kvm.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <vector>

inline void die_on(bool is_failure, const char *name)
{
  if (is_failure) {
    perror(name);
    exit(EXIT_FAILURE);
  }
}

/* A convencience RAII wrapper around file descriptors */
class fd_wrapper
{
  int fd_;
  bool invalidated = false;
public:
  int fd() const { return fd_; }

  fd_wrapper(int fd)
    : fd_(fd)
  {
    die_on(fd_ < 0, "fd create");
  }

  fd_wrapper(const char *fname, int flags)
    : fd_(open(fname, flags))
  {
    die_on(fd_ < 0, "open");
  }

  fd_wrapper(fd_wrapper &&other)
    : fd_(other.fd())
  {
    /* Prevent double close */
    other.invalidated = true;
  }

  /* Can't copy this class only move it. */
  fd_wrapper(fd_wrapper const &) = delete;

  ~fd_wrapper()
  {
    if (not invalidated)
      die_on(close(fd_) < 0, "close");
  }
};

class kvm_vcpu {
  fd_wrapper vcpu_fd;

  size_t vcpu_mmap_size_;
  kvm_run *run_;

public:
  kvm_vcpu(kvm_vcpu const &) = delete;
  kvm_vcpu(kvm_vcpu &&) = default;

  kvm_run *get_state() { return run_; }

  void run()
  {
    die_on(ioctl(vcpu_fd.fd(), KVM_RUN, 0) < 0, "KVM_RUN");
  }

  kvm_regs get_regs()
  {
    kvm_regs regs;
    die_on(ioctl(vcpu_fd.fd(), KVM_GET_REGS, &regs) < 0, "KVM_GET_REGS");
    return regs;
  }

  kvm_sregs get_sregs()
  {
    kvm_sregs sregs;
    die_on(ioctl(vcpu_fd.fd(), KVM_GET_SREGS, &sregs) < 0, "KVM_GET_SREGS");
    return sregs;
  }

  void set_regs(kvm_regs const &regs)
  {
    die_on(ioctl(vcpu_fd.fd(), KVM_SET_REGS, &regs) < 0, "KVM_SET_REGS");
  }

  void set_sregs(kvm_sregs const &sregs)
  {
    die_on(ioctl(vcpu_fd.fd(), KVM_SET_SREGS, &sregs) < 0, "KVM_SET_SREGS");
  }


  void set_cpuid(std::vector<kvm_cpuid_entry2> const &entries)
  {
    char backing[sizeof(kvm_cpuid2) + entries.size()*sizeof(kvm_cpuid_entry2)] {};
    kvm_cpuid2 *leafs = reinterpret_cast<kvm_cpuid2 *>(backing);
    int rc;

    leafs->nent = entries.size();
    std::copy_n(entries.begin(), entries.size(), leafs->entries);
    rc = ioctl(vcpu_fd.fd(), KVM_SET_CPUID2, leafs);
    die_on(rc != 0, "ioctl(KVM_SET_CPUID2)");
  }

  kvm_vcpu(int fd, size_t mmap_size)
    : vcpu_fd(fd), vcpu_mmap_size_(mmap_size)
  {
    run_ = static_cast<kvm_run *>(mmap(nullptr, mmap_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0));
    die_on(run_ == MAP_FAILED, "mmap");
  }

  ~kvm_vcpu()
  {
    die_on(munmap(run_, vcpu_mmap_size_) < 0, "munmap");
  }
};

/* A convencience RAII wrapper around /dev/kvm. */
class kvm {
  fd_wrapper dev_kvm { "/dev/kvm", O_RDWR };
  fd_wrapper vm { ioctl(dev_kvm.fd(), KVM_CREATE_VM, 0) };

  int memory_slots_ = 0;

public:

  size_t get_vcpu_mmap_size()
  {
    int size = ioctl(dev_kvm.fd(), KVM_GET_VCPU_MMAP_SIZE, 0);

    die_on(size < 0, "KVM_GET_VCPU_MMAP_SIZE");
    return (size_t)size;
  }

  void add_memory_region(uint64_t gpa, uint64_t size, void *backing, bool readonly = false)
  {
    int rc;
    const kvm_userspace_memory_region slotinfo { (uint32_t)memory_slots_,
                                                 (uint32_t)(readonly ? KVM_MEM_READONLY : 0),
                                                 gpa, size, (uintptr_t)backing };

    rc = ioctl(vm.fd(), KVM_SET_USER_MEMORY_REGION, &slotinfo);
    die_on(rc < 0, "KVM_SET_USER_MEMORY_REGION");

    memory_slots_++;
  }

  void add_memory_region(uint64_t gpa, uint64_t size, void const *backing)
  {
    add_memory_region(gpa, size, const_cast<void *>(backing), true);
  }

  kvm_vcpu create_vcpu(int apic_id)
  {
    return { ioctl(vm.fd(), KVM_CREATE_VCPU, apic_id), get_vcpu_mmap_size() };
  }

  std::vector<kvm_cpuid_entry2> get_supported_cpuid()
  {
    const size_t max_cpuid_leafs = 128;
    char backing[sizeof(kvm_cpuid2) + max_cpuid_leafs*sizeof(kvm_cpuid_entry2)] {};
    kvm_cpuid2 *leafs = reinterpret_cast<kvm_cpuid2 *>(backing);
    int rc;

    leafs->nent = max_cpuid_leafs;
    rc = ioctl(dev_kvm.fd(), KVM_GET_SUPPORTED_CPUID, leafs);
    die_on(rc != 0, "ioctl(KVM_GET_SUPPORTED_CPUID)");

    return { &leafs->entries[0], &leafs->entries[leafs->nent] };
  }
};
