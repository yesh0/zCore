#include "bpf.h"
#include "kprobe.h"

int bpf_prog(struct kprobe_bpf_ctx *ctx) {
  size_t * ptr = (size_t *) ctx->tf.regs;
  // Invalid offset
  bpf_trace_printk("bpf prog triggered!\n", ptr[128], 0, 0);

  return 0;
}