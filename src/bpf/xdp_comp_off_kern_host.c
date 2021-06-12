#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "util_host_tmt.h"
#include "util_host_rtg.h"

#include "../shared.h"


SEC("XDPEP")
int xdp_entry_point(struct xdp_md* ctx) {

	struct hkey_t hkey = {};

	process_custom_telemetry_meta(ctx);

	get_hkey_cm(ctx, &hkey); //get 5-tuple to use on the matches

	//do the matches and populate route of XDP progs for the packet
	mt_all(ctx);

	mt_proto(ctx, &hkey);

	mt_dstip(ctx, &hkey);

	//route the packet
	bpf_tail_call(ctx, &rtg_ind_table_map, 0);

	return XDP_PASS;
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

	if (cm->type != META_TYPE_HLL)
		return XDP_PASS;

	cur_fd_ptr = cm->fd_prog_ptr;

	if (cur_fd_ptr == cm->total_prgs)
	{
		remove_meta(ctx);
		return XDP_PASS; // when we will drop a packet?
	}
	else
	{
		cur_fd_prog = get_cur_fd_prog(cur_fd_ptr, cm);
		cm->fd_prog_ptr++;
		//send to the next app
		bpf_tail_call(ctx, &rtg_table_map, cur_fd_prog);
	}
	remove_meta(ctx);
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
