// SPDX-License-Identifier: GPL-2.0

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
#include <signal.h>
#include <time.h>
#include <sys/syscall.h>
#include <sys/signalfd.h>
#include <unistd.h>

#include "kvm.hpp"

/* This code is mapped into the guest at GPA 0. */
static unsigned char guest_code[] alignas(4096) {
#include "guest.inc"
                               };

static const uint64_t page_size = 4096;

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
  uint64_t gpa_;    /* GPA of page tables */
  uint64_t *tables_;

  /*
   * Helper functions to get pointers to different levels of the paging
   * hierarchy.
   */
  uint64_t *pml4() { return tables_; }
  uint64_t *pdpt() { return tables_ + 1 * page_size/sizeof(uint64_t); }

public:

  page_table(kvm *kvm, uint64_t gpa)
  {
    die_on(gpa % page_size != 0, "Page table GPA not aligned");

    tables_ = static_cast<uint64_t *>(aligned_alloc(page_size, tables_size_));
    die_on(tables_ == nullptr, "aligned_alloc");
    memset(tables_, 0, tables_size_);

    /* Create a 1:1 mapping for the low GB */
    pml4()[0] = (gpa + page_size) | page_pws;
    pdpt()[0] = 0 | page_pws | page_large;

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

class timeout_vm {
  /* Page tables are located after guest code. */
  uint64_t const page_table_base = sizeof(guest_code);

  kvm kvm_;
  kvm_vcpu vcpu_ { kvm_.create_vcpu(0) };
  page_table page_table_ { &kvm_, page_table_base };

  timer_t timer;
  int timer_signal_fd;

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
   * Runs the VM and returns how many loops the guest code executed.
   */
  uint64_t run()
  {
    auto state = vcpu_.get_state();

    kvm_regs regs {};

    regs.rflags = 2; /* reserved bit */
    regs.rax = 0;
    regs.rip = 0;

    vcpu_.set_regs(regs);
    vcpu_.run();

    regs = vcpu_.get_regs();

    die_on(state->exit_reason != KVM_EXIT_INTR, "unexpected exit");

    return regs.rax;
  }

  void clear_pending_timer_event()
  {
    struct signalfd_siginfo si;
    int rc;

    rc = read(timer_signal_fd, &si, sizeof(si));
    die_on(rc != sizeof(si) && errno != EAGAIN, "failed to clear timer");
  }

  /*
   * Program a relative timeout.
   *
   * This timeout starts running now. When it expires, KVM_RUN will return EINTR with exit reason KVM_EXIT_INTR.
   */
  template <typename REP, typename PERIOD>
  void arm_timer(std::chrono::duration<REP, PERIOD> rel_timeout)
  {
    // SIGUSR1 stays pending until we clear it. If we don't, the next KVM_RUN will immediately exit with EINTR.
    clear_pending_timer_event();

    auto ns = std::chrono::duration_cast<std::chrono::nanoseconds>(rel_timeout);

    struct itimerspec tspec = {
      .it_interval = {},
      .it_value = {
        .tv_sec = static_cast<time_t>(ns.count() / 1000000000L),
        .tv_nsec = static_cast<long>(ns.count() % 1000000000L),
      },
    };

    die_on(timer_settime(timer, 0 /* relative timeout */, &tspec, nullptr) != 0, "failed to set timer");
  }

  timeout_vm()
  {
    kvm_.add_memory_region(0, sizeof(guest_code), guest_code);

    enable_long_mode();


    // Create timer that fires SIGUSR1 when it expires.
    struct sigevent sevp {};

    sevp.sigev_notify = SIGEV_THREAD_ID;

    // Make sure we get timers on this thread.
    sevp._sigev_un._tid = gettid();

    sevp.sigev_signo = SIGUSR1;

    die_on(timer_create(CLOCK_MONOTONIC, &sevp, &timer) != 0, "failed to create timer");

    // Block SIGUSR1 from actually being delivered to this thread.
    sigset_t sigset;
    sigemptyset(&sigset);
    sigaddset(&sigset, SIGUSR1);

    sigset_t sigset_old;
    die_on(pthread_sigmask(SIG_BLOCK, &sigset, &sigset_old) != 0, "failed to block signal");

    // KVM allows us to atomically swap the signal mask. We set the original signal mask here, which allows SIGUSR1 to
    // interrupt KVM_RUN.
    vcpu_.set_signal_mask(sigset_old);

    // Create a signalfd for clear_pending_timer_event(). The alternative would be to actually deliver the signal to
    // clear itm which would require calls to sigprocmask.
    timer_signal_fd = signalfd(-1, &sigset, SFD_NONBLOCK);
    die_on(timer_signal_fd < 0, "failed to create signalfd");
  }
};

int main()
{
  timeout_vm vm;

  vm.arm_timer(std::chrono::milliseconds{1});
  uint64_t reps1 = vm.run();


  vm.arm_timer(std::chrono::milliseconds{2});
  uint64_t reps2 = vm.run();

  std::cout << "Reps: " << reps1 << std::endl;
  std::cout << "Reps: " << reps2 << std::endl;

  return 0;
}
