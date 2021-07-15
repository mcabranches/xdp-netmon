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

#endif