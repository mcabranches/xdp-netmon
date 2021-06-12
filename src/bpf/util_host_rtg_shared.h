#ifndef UTIL_HOST_RTG_SHARED_H
#define UTIL_HOST_RTG_SHARED_H

#include <linux/bpf.h>

//This is needed to avoid table conflicts between the router and apps
//Populate this with routing section in main XDP entry point
struct bpf_map_def SEC("maps") rtg_ind_table_map = {
	.type = BPF_MAP_TYPE_PROG_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u32),
	.max_entries = 1,
};

#endif