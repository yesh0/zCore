#include "bpf.h"

extern int map_fd;

int foo()
{
    int key, old_value, new_value;
    key = 0;
    old_value = * (int *) bpf_map_lookup_elem(map_fd, &key);
    new_value = old_value + 1;

    bpf_map_update_elem(map_fd, &key, &new_value, 0);
    bpf_trace_printk("value = {}", old_value, 0, 0);

    return 1;
}
