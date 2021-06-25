#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "util_host_tmt.h"
#include "util_host_rtg.h"

#include "../shared.h"

struct bpf_map_def SEC("maps") eoc_counter_map = {
        .type        = BPF_MAP_TYPE_PERCPU_ARRAY,
        .key_size    = sizeof(__u32),
        .value_size  = sizeof(struct stats),
        .max_entries = 1
};

SEC("XDPEP")
int xdp_entry_point(struct xdp_md* ctx) {

	struct hkey_t hkey = {};

	process_custom_telemetry_meta(ctx);

	get_hkey_cm(ctx, &hkey); //get 5-tuple to use on the matches

	//do the matches and populate route of XDP progs for the packet
	mt_all(ctx);

	mt_proto(ctx, &hkey);

	mt_dstip(ctx, &hkey);

	mt_port(ctx, &hkey);

	//route the packet - user space app add "xdp_route_pkt()" to "rtg_ind_table_map"
	bpf_tail_call(ctx, &rtg_ind_table_map, 0);

	return XDP_DROP;
}

SEC("XDPRTG")
int xdp_route_pkt(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct custom_meta_desc *cm;
	__u16 cur_fd_ptr;
	__u16 cur_fd_prog;

	cm = data;

	if (!((void *)cm + sizeof(*cm) <= data_end))
	{
		return XDP_ABORTED;	
	}

	//need to fix this. If packet is GPV and the traffic is not monitored
	//(do not match on "do_telemetry() on the NIC"), the GPV packet will be sent
	//to kernel. Add a test to see if packet is UDP and has GPV dst port
	if (cm->type != META_TYPE_HLL) 
		return XDP_DROP; //just for benchmarks
		//return XDP_PASS

	cur_fd_ptr = cm->fd_prog_ptr;

	if (cur_fd_ptr < cm->total_prgs)
	{
		cur_fd_prog = get_cur_fd_prog(cur_fd_ptr, cm);
		cm->fd_prog_ptr++;
		//send to the next app
		bpf_tail_call(ctx, &rtg_table_map, cur_fd_prog);
	}

	remove_meta(ctx);

	//end of chain counter
	__u32 key = 0;
    struct stats* stats = bpf_map_lookup_elem(&eoc_counter_map, &key);
    data = (void *)(__u64) ctx->data;
    data_end = (void *)(__u64) ctx->data_end;

    if (stats) 
	{
    	stats->bytes += (__u64)data_end - (__u64)data;
        stats->pkts += 1;
    }

	return XDP_DROP;
}

char _license[] SEC("license") = "GPL";
