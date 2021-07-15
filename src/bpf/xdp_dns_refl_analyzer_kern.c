#include <arpa/inet.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include "../shared.h"
#include "util_host_rtg_shared.h"

#define GPV_HDR_OFFSET 42 // + 42 (eth - 14, ip - 20, udp - 8)

struct bpf_map_def SEC("maps") xdp_dns_gpv_flows_map = {
	.type        = BPF_MAP_TYPE_HASH,
	.key_size    = sizeof(struct ip4_5tuple),
	.value_size  = sizeof(struct flow_table_entry),
	.max_entries = 65536
};

struct bpf_map_def SEC("maps") xdp_dns_flows_map = {
	.type        = BPF_MAP_TYPE_HASH,
	.key_size    = sizeof(struct hkey_t),
	.value_size  = sizeof(struct flow_table_entry),
	.max_entries = 65536
};


SEC("XDPDRA")
int dns_refl_analyzer(struct xdp_md* ctx) {
	
	//bpf_debug("dns_refl_analyzer\n");

	//logic goes here
	void* data = (void*)(unsigned long) ctx->data;
	void* data_end = (void*)(unsigned long) ctx->data_end;
	__u8 is_gpv;
	struct flow_table_entry init_entry = { .timestamp = 0, .stats = { .bytes = 0, .pkts  = 1 } };

	//Test if this is GPV packet
	is_gpv = test_gpv(ctx);

	//logic goes here

	if (is_gpv) 
	{	
		if (data + CUSTOM_META_OFFSET + GPV_HDR_OFFSET + sizeof(struct gpv_pkt_t) <= data_end) { // correct parsing must be ensured in main xdp prog
	
			struct gpv_pkt_t* gpv_h = (data + CUSTOM_META_OFFSET + GPV_HDR_OFFSET);

        	if (ntohs(gpv_h->tp_src) == 53 || ntohs(gpv_h->tp_dst) == 53) {
            
            	struct ip4_5tuple* ip45t = (data + CUSTOM_META_OFFSET + GPV_HDR_OFFSET);
            	struct flow_table_entry* entry = bpf_map_lookup_elem(&xdp_dns_gpv_flows_map, ip45t);

            	if (!entry) {
                	if (bpf_map_update_elem(&xdp_dns_gpv_flows_map, ip45t, &init_entry, BPF_NOEXIST)) {
                    	//bpf_debug("dns_flows: added entry\n");
                	} else {
                    	// bpf_debug("dns_flows: failed adding entry\n");
                	}
            	} else {
                	entry->stats.pkts += 1;
                	//bpf_debug("dns_flows: incremented existing entry\n");
            	}
        	}
		}
	}
	else
	{
		//process as a vanilla DNS packet
		//bpf_debug("Vanilla DNS packet\n");
		
		struct hkey_t hkey = {};
        get_hkey_cm_app(ctx, &hkey);
        
		if (ntohs(hkey.saddr) == 53 || ntohs(hkey.dport) == 53) {
            
            struct flow_table_entry* entry = bpf_map_lookup_elem(&xdp_dns_flows_map, &hkey);

            if (!entry) {
                if (bpf_map_update_elem(&xdp_dns_flows_map, &hkey, &init_entry, BPF_NOEXIST)) {
                	//bpf_debug("dns_flows: added entry\n");
                } else {
                	//bpf_debug("dns_flows: failed adding entry\n");
                	}
            } else {
            	entry->stats.pkts += 1;
                //bpf_debug("dns_flows: incremented existing entry\n");
            }
       }
			
	}

	//route the packet
	bpf_tail_call(ctx, &rtg_ind_table_map, 0);

	bpf_debug("App could not route the packet ... Dropping \n");

	return XDP_DROP;
}


char _license[] SEC("license") = "GPL";
