#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "util_nic.h"
#include "util_host_tmt.h"
#include "util_host_rtg.h"
#include "../shared.h"


SEC("XDP1")
int xdp_entry_router(struct xdp_md* ctx) {

	struct hkey_t hkey = {};

    get_hkey(ctx, &hkey); //get 5-tuple

	if (do_telemetry(&hkey) == 1)
	{
		gen_meta_udp_hll(ctx);
		update_counter(ctx, hkey);
		update_cms(ctx, hkey);
	}

	process_custom_telemetry_meta(ctx);

	get_hkey_cm(ctx, &hkey); //get 5-tuple to use on the matches

	//do the matches and populate route of XDP progs for the packet 
	mt_all(ctx);

	mt_proto(ctx, &hkey);

	mt_dstip(ctx, &hkey);

	//route the packet
	route_pkt(ctx);

	return XDP_PASS;
}


//Move each of the next sections to their own file
SEC("XDP2")
int loop_analyzer(struct xdp_md* ctx) {

	bpf_debug("loop_analyzer\n");

	//logic goes here

	route_pkt(ctx);

	return XDP_PASS;
}

SEC("XDP3")
int syn_flood_analyzer(struct xdp_md* ctx) {

	bpf_debug("syn_flood_analyzer\n");

	//logic goes here

	route_pkt(ctx);

	return XDP_PASS;
}

SEC("XDP4")
int traffic_accounting(struct xdp_md* ctx) {

	bpf_debug("traffic_accounting\n");

	//logic goes here

	route_pkt(ctx);

	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
