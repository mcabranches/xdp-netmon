#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "util_nic.h"
#include "../shared.h"


SEC("xdp")
int xdp_pass(struct xdp_md* ctx) {

	struct hkey_t hkey = {};
	__u32 hash;

	get_hkey(ctx, &hkey); //get 5-tuple

	//simple GPV LB
	//set number of queues on the NIC: $sudo ethtool -L enp4s0np0np0 combined 8
	hash = jhash(&hkey, sizeof(struct hkey_t), 0xdeadbeef);
	ctx->rx_queue_index = (hash % 2);
	
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";