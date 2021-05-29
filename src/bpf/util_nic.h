
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
* 2nd entry gets stats for TCP and 3rd for UDP 
*/
struct bpf_map_def SEC("maps") counter_map = {
	.type        = BPF_MAP_TYPE_ARRAY,
	.key_size    = sizeof(__u32),
	.value_size  = sizeof(struct stats),
	.max_entries = 3
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
					hkey->sport = bpf_ntohs(udp->source);
					hkey->dport = bpf_ntohs(udp->dest);
					hkey->saddr = bpf_ntohl(ip->saddr);
					hkey->daddr = bpf_ntohl(ip->daddr);
				}
			}
			else if (ip->protocol == 6)
			{
				struct tcphdr *tcp = (void *)ip + sizeof(*ip);
            	if ((void *)tcp + sizeof(*tcp) <= data_end)
            	{
					hkey->sport = bpf_ntohs(tcp->source);
					hkey->dport = bpf_ntohs(tcp->dest);
					hkey->saddr = bpf_ntohl(ip->saddr);
					hkey->daddr = bpf_ntohl(ip->daddr);
				}
			}
		}
	}	
	return 1;
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

//We should have something similar to count GPV data
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

static __always_inline __u32 five_tuple_hash_gpv(struct gpv_pkt_t *gpv_pkt)
{
	struct gpv_pkt_t hkey;
	__u32 hash;
	if (gpv_pkt)
	{
		hkey.ip_src = gpv_pkt->ip_src;
		hkey.ip_dst = gpv_pkt->ip_dst;
		hkey.tp_src = gpv_pkt->tp_src;
		hkey.tp_dst = gpv_pkt->tp_dst;
		hkey.ip_proto = gpv_pkt->ip_proto;
		hash = jhash(&hkey, sizeof(struct gpv_pkt_t), 0x5678);
		return hash;
	}
	else 
		return -1;
}

static __always_inline __u32 five_tuple_hash_udp(struct hkey_t udp_key)
{
	__u32 hash;
	hash = jhash(&udp_key, sizeof(struct hkey_t), 0x5678);
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

	//Verfy if generic UDP should be monitored
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


static __always_inline int build_meta_gpv(struct gpv_pkt_t *gpv_pkt, struct custom_meta_desc *meta)
{
	__u32 hash;
	__u32 num_zeroes;

	hash = five_tuple_hash_gpv(gpv_pkt);
	num_zeroes = count_num_zeroes(hash);
	meta->hash = hash;
	meta->num_zeros = num_zeroes;
	meta->fd_prog_ptr = 0;

	return 1;
}

//this also works for TCP. So change the function's name
static __always_inline int build_meta_udp(struct hkey_t udp_key, struct custom_meta_desc *meta)
{
	__u32 hash;
	__u32 num_zeroes;
	__u32 bucket;

	hash = five_tuple_hash_udp(udp_key);
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

static __always_inline int gen_meta_gpv_hll(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
  	struct ethhdr *eth = data;
	struct gpv_pkt_t *gpv_pkt = NULL;
	struct custom_meta_desc meta;

	if ((void *)eth + sizeof(*eth) <= data_end)
    	{
        	struct iphdr *ip = data + sizeof(*eth);
        	if ((void *)ip + sizeof(*ip) <= data_end)
        	{
			gpv_pkt = (void *)ip + sizeof(struct iphdr) + sizeof(struct udphdr);
			if ((void *)gpv_pkt + sizeof(*gpv_pkt) <= data_end)
			{
				build_meta_gpv(gpv_pkt, &meta);
				
				write_meta(ctx, &meta);
			}
        	}
    	}
	return XDP_PASS;
}

//adap this to support TCP as well
static __always_inline int gen_meta_udp_hll(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
	struct udphdr *udp_pkt = NULL;
	struct hkey_t udp_key;
	struct custom_meta_desc meta;

	if ((void *)eth + sizeof(*eth) <= data_end)
    {
		struct iphdr *ip = data + sizeof(*eth);
        	
		if ((void *)ip + sizeof(*ip) <= data_end)
        	{
			udp_pkt = (void *)ip + sizeof(struct iphdr);
			
			if ((void *)udp_pkt + sizeof(*udp_pkt) <= data_end)
			{
				udp_key.saddr = ip->saddr;
				udp_key.daddr = ip->daddr;
				udp_key.sport = udp_pkt->source;
				udp_key.dport = udp_pkt->dest;
			
				build_meta_udp(udp_key, &meta);
				write_meta(ctx, &meta);
			}
        }
    }
	return XDP_PASS;
}

#endif