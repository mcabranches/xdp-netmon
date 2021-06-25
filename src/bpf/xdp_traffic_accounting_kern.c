#include <arpa/inet.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include "../shared.h"
#include "util_host_rtg_shared.h"

#define GPV_HDR_OFFSET 42 // + 42 (eth - 14, ip - 20, udp - 8)

struct bpf_map_def SEC("maps") counter_map = {
        .type        = BPF_MAP_TYPE_PERCPU_ARRAY,
        .key_size    = sizeof(__u32),
        .value_size  = sizeof(struct stats),
        .max_entries = 1
};

struct bpf_map_def SEC("maps") traffic_account_map = {
        .type        = BPF_MAP_TYPE_PERCPU_HASH,
        .key_size    = sizeof(__u32),
        .value_size  = sizeof(__u64),
        .max_entries = 65536
};


SEC("XDPTA")
int traffic_accounting(struct xdp_md* ctx) {

        //bpf_debug("traffic_accounting\n");

        //logic goes here

        void* data = (void*)(unsigned long) ctx->data;
        void* data_end = (void*)(unsigned long) ctx->data_end;
        unsigned pkt_len = data_end - data;
        __u8 is_gpv;

        //Test if this is GPV packet
        is_gpv = test_gpv(ctx);

        __u32 counter_key = 0;
        __u32 one = 1;

        if (is_gpv)
        {
                struct stats* stats = bpf_map_lookup_elem(&counter_map, &counter_key);

                if (stats) {
                        stats->bytes += pkt_len;
                        stats->pkts += 1;
                }

                if (data + CUSTOM_META_OFFSET + GPV_HDR_OFFSET + sizeof(struct gpv_pkt_t) <= data_end) { // correct parsing must be ensured in main xdp prog

                        struct gpv_pkt_t* gpv_h = (data + CUSTOM_META_OFFSET + GPV_HDR_OFFSET);
                        __u32* ip_dst = &(gpv_h->ip_dst);
                        __u64* entry = bpf_map_lookup_elem(&traffic_account_map, ip_dst);

                        if (!entry) {
                                if (bpf_map_update_elem(&traffic_account_map, ip_dst, &one, BPF_NOEXIST)) {
                                        //bpf_debug("traffic_account: added entry\n");
                                } else {
                                        //bpf_debug("traffic_account: failed adding entry\n");
                                }
                        } else {
                                *entry += 1;
                                 //bpf_debug("traffic_account: incremented existing entry\n");
                        }
                }
        }
                else
        {
                //Add code to process as a vanilla packet
                bpf_debug(" Vanilla packet\n");
        }


        //route the packet
        bpf_tail_call(ctx, &rtg_ind_table_map, 0);

        bpf_debug("App could not route the packet ... Dropping \n");

        return XDP_DROP;
}

char _license[] SEC("license") = "GPL";