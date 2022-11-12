#include <linux/bpf.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <syscall.h>
#include <inttypes.h>

int main() {
    syscall(SYS_bpf, , NULL, 0);
    // while (1) ;
    return 0;
}
