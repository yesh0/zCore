#include "bpf.h"
#include "kprobe.h"

int bpf_prog(struct kprobe_bpf_ctx *ctx) {
  bpf_trace_printk("triggered!\n", 0, 0, 0);
  // report tracepoint type
  if (ctx->ptype == 0)
    bpf_trace_printk("kprobe", 0, 0, 0);
  else if (ctx->ptype == 1)
    bpf_trace_printk("kretprobe@entry", 0, 0, 0);
  else
    bpf_trace_printk("kretprobe@exit", 0, 0, 0);

  // report tracepoint address
  bpf_trace_printk("\taddr = {}\n", ctx->paddr, 0, 0);

  // report registers
  for (int i = 0; i < 32; ++i) {
    bpf_trace_printk("r{}", i, 0, 0);
    if (i < 10)
      bpf_trace_printk(" ", 0, 0, 0);
    bpf_trace_printk(" = {}\n", ctx->tf.regs[i], 0, 0);
  }

  return 0;
}