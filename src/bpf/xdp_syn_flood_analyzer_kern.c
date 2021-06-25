#include <arpa/inet.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include "../shared.h"
#include "util_host_rtg_shared.h"

#define GPV_PKT_TIMESTAMP_MASK 0xffffffffffff0000

#define TCP_FLAG_SYN 0x02

#define TCP_FLAG_ACK 0x10


struct bpf_map_def SEC("maps") xdp_syn_flood_analyzer_map = {
	.type = BPF_MAP_TYPE_ARRAY, //change to percpu
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u32),
	.max_entries = 1,
};

struct bpf_map_def SEC("maps") xdp_syn_track_map = {
	.type        = BPF_MAP_TYPE_HASH,
	.key_size    = sizeof(struct ip4_5tuple),
	.value_size  = sizeof(__u64),
	.max_entries = 1024
};

static __u64 reverse_byte_order_long(__u64 a) {
	return ((a & 0xff00000000000000u) >> 56)
		| ((a & 0x00ff000000000000u) >> 40)
		| ((a & 0x0000ff0000000000u) >> 24)
		| ((a & 0x000000ff00000000u) >>  8)
		| ((a & 0x00000000ff000000u) <<  8)
		| ((a & 0x0000000000ff0000u) << 24)
		| ((a & 0x000000000000ff00u) << 40)
		| ((a & 0x00000000000000ffu) << 56);
}

SEC("XDPSFA")
int syn_flood_analyzer(struct xdp_md* ctx) {

	//bpf_debug("syn_flood_analyzer\n");

	//logic goes here
	void* data = (void*)(unsigned long) ctx->data;
	void* data_end = (void*)(unsigned long) ctx->data_end;
	__u8 is_gpv;

	//Test if this is GPV packet
	is_gpv = test_gpv(ctx);

	if (is_gpv) {	
		if (data + CUSTOM_META_OFFSET + GPV_HDR_OFFSET + sizeof(struct gpv_pkt_t) <= data_end) { // correct parsing must be ensured in main xdp prog

			struct gpv_pkt_t* gpv_h = (data + CUSTOM_META_OFFSET + GPV_HDR_OFFSET);
		
			if (gpv_h->ip_proto == 6) { 
				
				// assuming gpv len = 1
				if (data + CUSTOM_META_OFFSET + GPV_HDR_OFFSET + sizeof(struct gpv_pkt_t) + sizeof(struct gpv_p_t) <= data_end) {
			
					struct gpv_p_t* gpv_p = (data + CUSTOM_META_OFFSET + GPV_HDR_OFFSET + sizeof(struct gpv_pkt_t));
					__u64 ts_len_host = reverse_byte_order_long(gpv_p->timestamp_size);
					__u64 ts = (ts_len_host & GPV_PKT_TIMESTAMP_MASK) >> 4;

					struct gpv_pd_tcp_t* pd_tcp = (data + CUSTOM_META_OFFSET + GPV_HDR_OFFSET + sizeof(struct gpv_pkt_t)) + 12;
					struct ip4_5tuple* ip45t = (data + CUSTOM_META_OFFSET + GPV_HDR_OFFSET);

					__u64* tracked = bpf_map_lookup_elem(&xdp_syn_track_map, ip45t);

					if ((pd_tcp->flags & TCP_FLAG_SYN) && !(pd_tcp->flags & TCP_FLAG_ACK)) {
						//bpf_debug("gpv: tcp/syn segment at %lu\n", ts);
					
						if (!tracked) {
							if (bpf_map_update_elem(&xdp_syn_track_map, ip45t, &ts, BPF_NOEXIST) == 0) {
								//bpf_debug("syn_flood_detect: untracked syn segment: added entry\n");
							} else { 
								//bpf_debug("syn_flood_detect: failed adding entry"); 
							}
						} else {
							//bpf_debug("syn_flood_detect: already tracked syn segment\n");
						}

					} else if (pd_tcp->flags & TCP_FLAG_ACK) {
						//bpf_debug("gpv: tcp/ack segment at %lu\n", ts);

						if (tracked) {
							if (bpf_map_delete_elem(&xdp_syn_track_map, ip45t) == 0) {
								//bpf_debug("syn_flood_detect: already tracked ack segment: removed entry\n");
							} else { 
								//bpf_debug("syn_flood_detect: failed removing entry"); 
							}
						} else {
							//bpf_debug("syn_flood_detect: untracked ack segment\n");
						}
					}
				}
			}
		}
	}
	else
	{
		//process as a vanilla TCP packet (to-do)
		//bpf_debug("Vanilla TCP packet\n");
	}


	//add a simple counter to test user space app
	//__u32 *counter;
	//__u32 key = 0;

	//counter = bpf_map_lookup_elem(&xdp_syn_flood_analyzer_map, &key);
	//if (counter){
	//	*counter += 1;
		//bpf_debug("Counter: %i \n", *counter);
	//}

	//route the packet
	bpf_tail_call(ctx, &rtg_ind_table_map, 0);

	bpf_debug("App could not route the packet ... Dropping \n");

	return XDP_DROP;
}

char _license[] SEC("license") = "GPL";
