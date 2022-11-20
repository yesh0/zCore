#include "bpf.h"

extern int map_fd;

int foo()
{
    bpf_trace_printk("enter map.o!", 0, 0, 0);
    bpf_trace_printk("mapf {}\n", map_fd, 0, 0);
    int key, old_value = 0xff, new_value, ret;
    key = 0;
    ret = * (int *) bpf_map_lookup_elem(map_fd, &key, &old_value);
    bpf_trace_printk("old value {}\n", old_value, 0, 0);

    bpf_trace_printk("update oldvalue++\n", 0, 0, 0);
    
    new_value = old_value + 1;

    bpf_map_update_elem(map_fd, &key, &new_value, 0);
    bpf_trace_printk("new value = {}\n", new_value, 0, 0);

    return 1;
}
