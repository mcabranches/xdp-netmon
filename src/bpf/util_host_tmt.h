#ifndef UTIL_HOST_TMT_H
#define UTIL_HOST_TMT_H

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "../shared.h"


struct bpf_map_def SEC("maps") map_hll_1 = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u32),
	.max_entries = NUM_BUCKETS,
};


static __always_inline int update_HLL(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct custom_meta_desc *cm;
	__u32 *cur_max_zeros;
	__u32 bucket;
	__u32 num_zeros;

	cm = data;
	//Add HLL data to map
	if ((void *)cm + sizeof(*cm) <= data_end)
	{
		bucket = cm->bucket;
		num_zeros = cm->num_zeros;
	}
	else
		return XDP_DROP;

	
	cur_max_zeros = (__u32 *)bpf_map_lookup_elem(&map_hll_1, &bucket);
    if (!cur_max_zeros)
	{
		//update with an initial value
		bpf_map_update_elem(&map_hll_1, &bucket, &num_zeros, BPF_NOEXIST);
	}
	
	else
	{
		if (num_zeros > *cur_max_zeros)
		{
			bpf_map_update_elem(&map_hll_1, &bucket, &num_zeros, BPF_EXIST);
		}
	}
	
	return XDP_PASS;
}


static __always_inline int process_custom_telemetry_meta(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct custom_meta_desc *cm;

	cm = data;

	if ((void *)cm + sizeof(*cm) <= data_end)
	{
		if (cm->type == META_TYPE_HLL)
		{
			update_HLL(ctx);
		}
		else 
			return 1;
	}


	return 1;
}

#endif