
#ifndef BPF_UTIL_H
#define BPF_UTIL_H

#include <linux/bpf.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <string.h>
#include <stdlib.h>
#include "jhash.h"
#include "../shared.h"


/* userspace sets sources for gpv telemetry */
struct bpf_map_def SEC("maps") do_telemetry_map = {
	.type        = BPF_MAP_TYPE_HASH,
	.key_size    = sizeof(struct hkey_t),
	.value_size  = sizeof(__u8), //this should contain a bitmap to determine desired telemetry
	.max_entries = 16
};


/* Stores pkt stats first entry gets totals. 
* 2nd entry gets stats for TCP, 3rd for UDP and 4th ICMP
*/
struct bpf_map_def SEC("maps") counter_map = {
	.type        = BPF_MAP_TYPE_ARRAY,
	.key_size    = sizeof(__u32),
	.value_size  = sizeof(struct stats),
	.max_entries = 4
};

/* Maps for count-min (start with 3 maps) - each map should have
*  a hash function - to test we are varying the seed on jhash2 
*/

struct bpf_map_def SEC("maps") map_cms_1 = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct stats),
	.max_entries = MAX_CMS_ELEM,
};

struct bpf_map_def SEC("maps") map_cms_2 = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct stats),
	.max_entries = MAX_CMS_ELEM,
};

struct bpf_map_def SEC("maps") map_cms_3 = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct stats),
	.max_entries = MAX_CMS_ELEM,
};

//match all fields map
struct bpf_map_def SEC("maps") mt_all_map = {
	.type = BPF_MAP_TYPE_HASH, 
	.key_size = sizeof(__u8),
	.value_size = sizeof(struct fd_list_t), 
	.max_entries = 1,
};

//match protocol map
struct bpf_map_def SEC("maps") mt_proto_map = {
	.type = BPF_MAP_TYPE_HASH, 
	.key_size = sizeof(__u8),
	.value_size = sizeof(struct fd_list_t),
	.max_entries = 2,
};

//match sport map
struct bpf_map_def SEC("maps") mt_sport_map = {
	.type = BPF_MAP_TYPE_HASH, 
	.key_size = sizeof(__u16),
	.value_size = sizeof(struct fd_list_t),
	.max_entries = 1024,
};

//match sport map
struct bpf_map_def SEC("maps") mt_dport_map = {
	.type = BPF_MAP_TYPE_HASH, 
	.key_size = sizeof(__u16),
	.value_size = sizeof(struct fd_list_t),
	.max_entries = 1024,
};

//match dst ip map
struct bpf_map_def SEC("maps") mt_dstip_map = {
	.type = BPF_MAP_TYPE_HASH, 
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct fd_list_t),
	.max_entries = 1024,
};

static __always_inline int get_hkey(const struct xdp_md* ctx, struct hkey_t *hkey) 
{
	void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;

	if ((void *)eth + sizeof(*eth) <= data_end) 
	{
		struct iphdr *ip = data + sizeof(*eth);

		if ((void *)ip + sizeof(*ip) <= data_end)
        {
			hkey->proto = ip->protocol;
			if (ip->protocol == 17)
        	{
				struct udphdr *udp = (void *)ip + sizeof(*ip);
            	if ((void *)udp + sizeof(*udp) <= data_end)
            	{
					if (bpf_ntohs(udp->dest) != GPV_DST_PORT)
					{
						hkey->is_gpv = 0;
						hkey->sport = bpf_ntohs(udp->source);
						hkey->dport = bpf_ntohs(udp->dest);
						hkey->saddr = bpf_ntohl(ip->saddr);
						hkey->daddr = bpf_ntohl(ip->daddr);
					}
					else //get hkey from gpv
					{
						struct gpv_pkt_t *gpv = (void *)udp + sizeof(*udp);
						if ((void *)gpv + sizeof(*gpv) <= data_end)
						{
							hkey->is_gpv = 1;
							hkey->proto = gpv->ip_proto;
							hkey->sport = gpv->tp_src;
							hkey->dport = gpv->tp_dst;
							hkey->saddr = gpv->ip_src;
							hkey->daddr = gpv->ip_dst;
						}
					}
				}
			}
			else if (ip->protocol == 6)
			{
				struct tcphdr *tcp = (void *)ip + sizeof(*ip);
            	if ((void *)tcp + sizeof(*tcp) <= data_end)
            	{
					hkey->is_gpv = 0;
					hkey->sport = bpf_ntohs(tcp->source);
					hkey->dport = bpf_ntohs(tcp->dest);
					hkey->saddr = bpf_ntohl(ip->saddr);
					hkey->daddr = bpf_ntohl(ip->daddr);
				}
			}
		}
	}	
	return -1;
}

static __always_inline unsigned pkt_bytes(const struct xdp_md* ctx)
{
	void* data     = (void *)(__u64) ctx->data;
	void* data_end = (void *)(__u64) ctx->data_end;
	return (data_end - data);
}

static __always_inline void update_counter_map(const struct xdp_md* ctx, __u32 key)
{
	struct stats *stats;
	unsigned num_bytes;

	stats = bpf_map_lookup_elem(&counter_map, &key);

    if (stats)
    {
		num_bytes = pkt_bytes(ctx);

    	__sync_fetch_and_add(&stats->pkts, 1);
		__sync_fetch_and_add(&stats->bytes, num_bytes);
	}
}

//We should have something similar to count GPV data (if it carries more than one pkt data)
static __always_inline void update_counter(const struct xdp_md* ctx, struct hkey_t hkey)
{
	__u32 key;

	//Update totals
	key = 0;
	update_counter_map(ctx, key);

	//Update per-protocol counts
	if(hkey.proto == 6)
		key = 1;
	else if (hkey.proto == 17)
		key = 2;
	else 
		key = -1; //invalid

	update_counter_map(ctx, key);
}


//Currently we update pkt and byte counts in Count-Min Sketch (CMS) 
static __always_inline int update_cms(struct xdp_md *ctx, struct hkey_t hkey)
{
	__u32 hash;
	__u32 key;
	struct stats *stats;

	unsigned num_bytes;

	num_bytes = pkt_bytes(ctx);

	//We should use different hash functions
	//To test we are just changing the seed for jhash

	//Update the CMS map 1
	hash = jhash(&hkey, sizeof(struct hkey_t), 0x1);
	key = hash % MAX_CMS_ELEM;

	stats = bpf_map_lookup_elem(&map_cms_1, &key);

	if (!stats)
	{
		return 0;
	}

	__sync_fetch_and_add(&stats->pkts, 1);
	__sync_fetch_and_add(&stats->bytes, num_bytes);


	//Update the CMS map 2
	hash = jhash(&hkey, sizeof(struct hkey_t), 0x2);
	key = hash % MAX_CMS_ELEM;

	stats = bpf_map_lookup_elem(&map_cms_2, &key);

	if (!stats)
	{
		return 0;
	}

	__sync_fetch_and_add(&stats->pkts, 1);
	__sync_fetch_and_add(&stats->bytes, num_bytes);


	//Update the CMS map 4
	hash = jhash(&hkey, sizeof(struct hkey_t), 0x3);
	key = hash % MAX_CMS_ELEM;

	stats = bpf_map_lookup_elem(&map_cms_3, &key);

	if (!stats)
	{
		return 0;
	}

	__sync_fetch_and_add(&stats->pkts, 1);
	__sync_fetch_and_add(&stats->bytes, num_bytes);

	return 1;
}

static __always_inline int write_meta(struct xdp_md *ctx, struct custom_meta_desc *meta)
{
	struct custom_meta_desc *cm;
	if (bpf_xdp_adjust_head(ctx, 0 - (int)sizeof(*cm)))
		return -1;
	void *data = (void *)(long)ctx->data;
   	void *data_end = (void *)(long)ctx->data_end;
	cm = data;
	if ((void *)cm + sizeof(*cm) <= data_end)
	{
		memcpy(cm, meta, sizeof(struct custom_meta_desc));
	}
		
	return 1;
}

static __always_inline __u32 five_tuple_hash(struct hkey_t hkey)
{
	__u32 hash;
	hash = jhash(&hkey, sizeof(struct hkey_t), 0x5678);
	return hash;
}

static __always_inline __u8 count_num_zeroes(__u32 x)
{
	__u32 n = 32, y = 0;

    if ((y = x >> 16) != 0)
        n = n - 16, x = y;

    if ((y = x >> 8) != 0)
        n = n - 8, x = y;

    if ((y = x >> 4) != 0)
        n = n - 4, x = y;

    if ((y = x >> 2) != 0)
        n = n - 2, x = y;

    if ((y = x >> 1) != 0)
        return n - 2;
	
    return n - x;
}

//do_telemetry - We should change this to support more conditions 
//like saddr, ports, etc
static __always_inline __u8 do_telemetry(struct hkey_t *hkey)
{
	struct hkey_t proto_hkey = { 0 };

	proto_hkey.proto = hkey->proto;

	__u8 *do_telemetry_bm = NULL;

	//Verfy if generic protocol should be monitored
	do_telemetry_bm = (__u8 *) bpf_map_lookup_elem(&do_telemetry_map, &proto_hkey);
	
	if (do_telemetry_bm)
	{
		if (*do_telemetry_bm == 1)
			return 1;
		else
			return 0;
	}	
	//now verify a specific 5-tuple as a telemetry source
	do_telemetry_bm = (__u8 *) bpf_map_lookup_elem(&do_telemetry_map, hkey);
	if (do_telemetry_bm)
	{
		if (*do_telemetry_bm == 1)
			return 1;
		else
			return 0;
	}	

	return -1;
}

static __always_inline int build_meta(struct hkey_t hkey, struct custom_meta_desc *meta)
{
	__u32 hash;
	__u32 num_zeroes;
	__u32 bucket;

	hash = five_tuple_hash(hkey);
	bucket = (hash & BUCKET_MASK) >> (32 - BUCKET_SHIFT);
	hash = hash << BUCKET_SHIFT;
	num_zeroes = count_num_zeroes(hash);
	meta->type = META_TYPE_HLL;
	meta->bucket = bucket;
	meta->hash = hash;
	meta->num_zeros = num_zeroes + 1;
	meta->fd_prog_ptr = 0;
	meta->total_prgs = 0;

	return 1;
}

static __always_inline void gen_meta_hll(struct xdp_md *ctx)
{
	
	struct hkey_t hkey = {};
	struct custom_meta_desc meta;

	get_hkey(ctx, &hkey);

	build_meta(hkey, &meta);

	write_meta(ctx, &meta);

	return;
}

static __always_inline void set_cur_fd_prog(__u16 fd_prog_ptr, __u16 cur_fd_prog, struct custom_meta_desc *cm)
{
	//This had to be hardcoded. The approach using dyamic index on an array 
	//will be rejected by the verifier (invalid memory access even with memory boundary checks...)
	//bpf_debug("setting: fd_prog_ptr %i, cur_fd_prog %i\n", fd_prog_ptr, cur_fd_prog);
	if (fd_prog_ptr == 0)
	{
		cm->fd_prog1 = cur_fd_prog;
		return;
	}

	else if (fd_prog_ptr == 1)
	{
		cm->fd_prog2 = cur_fd_prog;
		return;
	}

	else if (fd_prog_ptr == 2)
	{
		cm->fd_prog3 = cur_fd_prog;
		return;
	}

	else if (fd_prog_ptr == 3)
	{
		cm->fd_prog4 = cur_fd_prog;
		return;
	}

	else if (fd_prog_ptr == 4)
	{
		cm->fd_prog5 = cur_fd_prog;
		return;
	}

	else
		return;
}


static __always_inline int write_fds_list(struct xdp_md *ctx, __u16 fds)
{
	struct custom_meta_desc *cm;
	void *data = (void *)(long)ctx->data;
   	void *data_end = (void *)(long)ctx->data_end;

	cm = data;

	if ((void *)cm + sizeof(*cm) <= data_end)
	{
		//We will only process packets that we set as of interest NIC map "do_telemetry_map"
		if (cm->type != META_TYPE_HLL)
		{
			return -1;

		}

		if (cm->fd_prog_ptr > MAX_CPO_PRGS)
			return -1;
		
		else
		{
			set_cur_fd_prog(cm->total_prgs, fds, cm);
			cm->total_prgs++;
		}	
	}

	return -1;

}

static __always_inline void mt_all(struct xdp_md *ctx)
{
	struct fd_list_t *fdl;

	__u8 key = 0;

	fdl = (struct fd_list_t *)bpf_map_lookup_elem(&mt_all_map, &key);

	if (fdl)
	{
		//bpf_debug("Matched all\n");

		//for (int i = 0; i < MAX_CPO_PRGS; i++)
			write_fds_list(ctx, fdl->fds[0]);
		
	}
}

static __always_inline void mt_port(struct xdp_md *ctx, struct hkey_t *hkey)
{
	struct fd_list_t *fdl;
	__u16 key;

	key = hkey->sport;
	fdl = (struct fd_list_t *)bpf_map_lookup_elem(&mt_sport_map, &key);

	if (fdl)
	{
		//bpf_debug("Matched sport\n");

		//for (int i = 0; i < MAX_CPO_PRGS; i++)
			write_fds_list(ctx, fdl->fds[0]);
			return; //write fdlist once 
	}
	else
	{
		key = hkey->dport;
		fdl = (struct fd_list_t *)bpf_map_lookup_elem(&mt_dport_map, &key);

		if (fdl)
		{
			//bpf_debug("Matched dport\n");
			write_fds_list(ctx, fdl->fds[0]);
		}
		return;
	}
}

static __always_inline void mt_proto(struct xdp_md *ctx, struct hkey_t *hkey)
{
	struct fd_list_t *fdl;

	__u8 key = hkey->proto; 

	fdl = (struct fd_list_t *)bpf_map_lookup_elem(&mt_proto_map, &key);

	if (fdl)
	{
		//bpf_debug("Matched proto\n");
		//for (int i = 0; i < MAX_CPO_PRGS; i++)
			write_fds_list(ctx, fdl->fds[0]);
	}
}

static __always_inline void mt_dstip(struct xdp_md *ctx, struct hkey_t *hkey)
{
	struct fd_list_t *fdl;

	fdl = (struct fd_list_t *)bpf_map_lookup_elem(&mt_dstip_map, &hkey->daddr);

	if (fdl)
	{
		//bpf_debug("Matched dst_ip\n");
		//for (int i = 0; i < MAX_CPO_PRGS; i++)
			write_fds_list(ctx, fdl->fds[0]);
	}
}

#endif