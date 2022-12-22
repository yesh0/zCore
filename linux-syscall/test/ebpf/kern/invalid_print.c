#include "bpf.h"
#include "kprobe.h"

int bpf_prog(struct kprobe_bpf_ctx *ctx) {
  // Invalid length
  const char string[] = "Hello World!";
  __bpf_trace_printk(string, sizeof(string) + 1, 0, 0, 0);

  return 0;
}