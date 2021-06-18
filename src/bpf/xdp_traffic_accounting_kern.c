#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "../shared.h"
#include "util_host_rtg_shared.h"

struct bpf_map_def SEC("maps") xdp_traffic_accounting_map = {
	.type = BPF_MAP_TYPE_HASH, //change to percpu
	.key_size = sizeof(__u16),
	.value_size = sizeof(struct fd_list_t),
	.max_entries = 65536,
};

SEC("XDPTA")
int traffic_accounting(struct xdp_md* ctx) {

	//bpf_debug("traffic_accounting\n");

	//logic goes here

	//route the packet
	bpf_tail_call(ctx, &rtg_ind_table_map, 0);

	bpf_debug("App could not route the packet ... Dropping \n");

	return XDP_DROP;
}

char _license[] SEC("license") = "GPL";