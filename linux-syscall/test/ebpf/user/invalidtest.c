#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <syscall.h>
#include <inttypes.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <string.h>
#include "bpf.h"

int main() {

    struct stat stat;
    int fd = open("./invalid.o", O_RDONLY);
    if (fd < 0) {
        printf("open kern prog failed!\n");
        return -1;
    }

    fstat(fd, &stat);
    uint64_t prog_size = stat.st_size;
    printf("file size = %ld\n", prog_size);

    // it seems like mmap with file mapping is not working
    // only use it as a way to allocate memory
    // todo try directly map file in zCore
    long ret = (long) mmap(NULL, prog_size, 3, 32, -1, 0);
    // cprintf("mmap returns %p\n", p);
    if (ret <= 0) {
        printf("mmap failed! ret = %ld\n", ret);
        close(fd);
        return 0;
    }

    unsigned *p = (unsigned *) ret;
    read(fd, p, prog_size);
    printf("ELF content: %x %x %x %x\n", p[0], p[1], p[2], p[3]);

    struct bpf_map_fd_entry map_array[] = {
    }; // empty
    int bpf_fd = bpf_prog_load_ex(p, prog_size, map_array, 0);
    printf("load ex: %x\n", bpf_fd);
    return 0;
}
