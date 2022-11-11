#include <bpf.h>
#include <file.h>
#include <ulib.h>
#include <stat.h>
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <syscall.h>

#define MAX_ENTRIES 32

void test_bpf_map() {
    int key;
    uint64_t value;

    int fd = bpf_create_map(BPF_MAP_TYPE_ARRAY, sizeof(key), sizeof(value), MAX_ENTRIES);
    assert(fd > 0);

    key = 3;
    assert(bpf_lookup_elem(fd, &key, &value) == 0);
    assert(value == 0);

    key = 3;
    value = 0x1122334455667788LL;
    assert(bpf_update_elem(fd, &key, &value, 0) == 0);

    key = MAX_ENTRIES + 1;
    assert(bpf_update_elem(fd, &key, &value, 0) < 0); // this should fail

    key = 3;
    assert(bpf_delete_elem(fd, &key) < 0); // this should fail

    assert(bpf_lookup_elem(fd, &key, &value) == 0);
    assert(value == 0x1122334455667788LL);

    cprintf("bpf map tests OK\n");
}

void test_bpf_hashmap() {
    uint64_t key, value, next_key;
    int fd = bpf_create_map(BPF_MAP_TYPE_HASH, sizeof(key), sizeof(value), MAX_ENTRIES);
    assert(fd > 0);

    for (int i = 1; i <= 10; ++i) {
        key = i * 0x2348fe12 + (86514 ^ i);
        value = i;
        cprintf("kv: (%lx, %ld)\n", key, value);
        assert(bpf_update_elem(fd, &key, &value, 0) == 0);
    }

    key = 0;
    while (bpf_get_next_key(fd, &key, &next_key) == 0) {
        key = next_key;
        assert(bpf_lookup_elem(fd, &key, &value) == 0);
        cprintf("got: (%lx, %ld)\n", key, value);
    }

    cprintf("bpf hashmap tests OK\n");
}

int create_map() {
    int fd = bpf_create_map(BPF_MAP_TYPE_ARRAY, sizeof(int), sizeof(int), MAX_ENTRIES);
    assert(fd > 0);

    int key = 0;
    int value = 12345;
    assert(bpf_update_elem(fd, &key, &value, 0) == 0);

    return fd;
}

void test_bpf_prog() {
    int map_fd = create_map();

    struct stat stat;
    int fd = open("./map.o", O_RDONLY);
    if (fd < 0) {
        cprintf("open file failed!\n");
        return;
    }

    fstat(fd, &stat);
    uint64_t prog_size = stat.st_size;
    cprintf("file size = %ld\n", prog_size);

    // it seems like mmap with file mapping is not working
    // only use it as a way to allocate memory
    long ret = (long) sys_mmap(NULL, prog_size, 3, 32, -1, 0);
    // cprintf("mmap returns %p\n", p);
    if (ret <= 0) {
        cprintf("mmap failed! ret = %ld\n", ret);
        close(fd);
        return;
    }

    unsigned *p = (unsigned *) ret;
    read(fd, p, prog_size);
    cprintf("ELF content: %x %x %x %x\n", p[0], p[1], p[2], p[3]);

    struct bpf_map_fd_entry map_array[] = {
        { .name = "map_fd", .fd = map_fd },
    };
    int bpf_fd = bpf_prog_load_ex(p, prog_size, map_array, 1);
    cprintf("load ex: %x\n", bpf_fd);

    // const char *target = "kprobe:_RNvMNtNtCs6EJUG5qC0e6_5rcore7syscall4procNtB4_7Syscall8sys_fork";
    const char *target = "kprobe:<rcore::syscall::Syscall>::sys_fork";
    cprintf("attach: %d\n", bpf_prog_attach(target, bpf_fd));

    close(fd);
}

void interrupt_handler(int sig) {
    cprintf("Ctrl-C received! (signal %d) Bye.\n", sig);
    exit(0);
}

int main() {
    test_bpf_hashmap();
    struct sigaction act = {
        .sa_handler = interrupt_handler,
        .sa_flags = 0,
        .sa_restorer = NULL,
        .sa_mask = 0,
    };
    sys_sigaction(SIGINT, &act, NULL);
    test_bpf_prog();
    // while (1) ;
    return 0;
}
