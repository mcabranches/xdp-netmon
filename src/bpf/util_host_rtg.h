#ifndef UTIL_HOST_RTG_H
#define UTIL_HOST_RTG_H

#include <linux/bpf.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <string.h>
#include <stdlib.h>
#include "../shared.h"


//This is needed to avoid table conflicts between the router and apps
//Populate this with routing section in main XDP entry point
struct bpf_map_def SEC("maps") rtg_ind_table_map = {
	.type = BPF_MAP_TYPE_PROG_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u32),
	.max_entries = 1,
};

struct bpf_map_def SEC("maps") rtg_table_map = {
	.type = BPF_MAP_TYPE_PROG_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u32),
	.max_entries = 16,
};

//match all fields map
struct bpf_map_def SEC("maps") mt_all_map = {
	.type = BPF_MAP_TYPE_HASH, //change to percpu
	.key_size = sizeof(__u8),
	.value_size = sizeof(struct fd_list_t), 
	.max_entries = 1,
};

//match protocol map
struct bpf_map_def SEC("maps") mt_proto_map = {
	.type = BPF_MAP_TYPE_HASH, //change to percpu
	.key_size = sizeof(__u16),
	.value_size = sizeof(struct fd_list_t),
	.max_entries = 2,
};

//match dst ip map
struct bpf_map_def SEC("maps") mt_dstip_map = {
	.type = BPF_MAP_TYPE_HASH, //change this to LPM Map
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct fd_list_t),
	.max_entries = 1024,
};

static __always_inline int get_hkey_cm(const struct xdp_md* ctx, struct hkey_t *hkey) 
{
	struct custom_meta_desc *cm;
	void *data = (void *)(long)ctx->data + sizeof(*cm);
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
	return -1;
}

static __always_inline int remove_meta(struct xdp_md *ctx)
{	//remove hll metadata
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct custom_meta_desc *cm;

	cm = data;

	if ((void *)cm + sizeof(*cm) <= data_end)
	{
		//only remove if we know metadata was added
		if (cm->type == META_TYPE_HLL)
		{
			bpf_xdp_adjust_head(ctx, (int)sizeof(struct custom_meta_desc));
		}
	}

	return -1;
}

static __always_inline __u16 get_cur_fd_prog(__u16 fd_prog_ptr, struct custom_meta_desc *cm)
{
	//This had to be hardcoded. The approach using dyamic index on an array 
	//will be rejected by the verifier (invalid memory access even with memory boundary checks...)

	if (fd_prog_ptr == 0)
		return cm->fd_prog1;

	else if (fd_prog_ptr == 1)
		return cm->fd_prog2;

	else if (fd_prog_ptr == 2)
		return cm->fd_prog3;

	else if (fd_prog_ptr == 3)
		return cm->fd_prog4;

	else if (fd_prog_ptr == 4)
		return cm->fd_prog5;

	else
		return 0;
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

static __always_inline void mt_proto(struct xdp_md *ctx, struct hkey_t *hkey)
{
	struct fd_list_t *fdl;

	fdl = (struct fd_list_t *)bpf_map_lookup_elem(&mt_proto_map, &hkey->proto);

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