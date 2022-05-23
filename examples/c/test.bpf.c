// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
#include <stdbool.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

struct foobar {
};

char LICENSE[] SEC("license") = "Dual BSD/GPL";

int my_pid = 0;

SEC("tp/syscalls/sys_enter_write")
int handle_tp(void *ctx)
{
  bool exists = bpf_core_type_exists(struct foobar);
	int pid = bpf_get_current_pid_tgid() >> 32;

	if (pid != my_pid)
		return 0;

  if (exists)
	  bpf_printk("BPF triggered from PID %d.\n", pid);
  else
	  bpf_printk("BPF triggered from PID %d (path 2).\n", pid);

	return 0;
}
