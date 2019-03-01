#!/bin/sh

set -e

# Different kernels disagree on whether to use dashes or commas.
sort /sys/devices/system/cpu/cpu*/topology/thread_siblings_list | sort -u | tr ',-' ' '
