#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "../shared.h"
#include "util_host_rtg_shared.h"

struct bpf_map_def SEC("maps") xdp_syn_flood_analyzer_map = {
	.type = BPF_MAP_TYPE_ARRAY, //change to percpu
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u32),
	.max_entries = 1,
};

SEC("XDPSFA")
int syn_flood_analyzer(struct xdp_md* ctx) {

	bpf_debug("syn_flood_analyzer\n");

	//logic goes here
	//add a simple counter to test
	__u32 *counter;
	__u32 key = 0;

	counter = bpf_map_lookup_elem(&xdp_syn_flood_analyzer_map, &key);
	if (counter){
		*counter += 1;
		bpf_debug("Counter: %i \n", *counter);
	}

	//route the packet
	bpf_tail_call(ctx, &rtg_ind_table_map, 0);

	bpf_debug("App could not route the packet ... Dropping \n");

	return XDP_DROP;
}

char _license[] SEC("license") = "GPL";