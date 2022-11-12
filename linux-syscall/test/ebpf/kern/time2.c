#include "bpf.h"

extern int time_counters, records;

int main()
{    
    u64 t2 = bpf_ktime_get_ns();
    int cpu = bpf_get_smp_processor_id();
    u64 t1 = * (u64 *) bpf_map_lookup_elem(time_counters, &cpu);
    u64 elapsed = t2 - t1;

    int index = 0;
    u64 count = * (u64 *) bpf_map_lookup_elem(records, &index);
    count += 1;
    bpf_map_update_elem(records, &index, &count, 0);

    index = count;
    bpf_map_update_elem(records, &index, &elapsed, 0);
    return 0;
}
