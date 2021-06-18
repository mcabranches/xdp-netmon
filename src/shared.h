
#ifndef SHARED_H
#define SHARED_H

#define META_TYPE_HLL 0x1234

#define GPV_DST_PORT 42742

#define bpf_debug(fmt, ...)\
({\
	char ____fmt[] = fmt;\
	bpf_trace_printk(____fmt, sizeof(____fmt),\
				##__VA_ARGS__);\
})


#define BUCKET_SHIFT 7

#if BUCKET_SHIFT == 4
	#define BUCKET_MASK 0xf0000000
#elif BUCKET_SHIFT == 5
	#define BUCKET_MASK 0xf8000000
#elif BUCKET_SHIFT == 6
	#define BUCKET_MASK 0xfc000000
#elif BUCKET_SHIFT == 7
	#define BUCKET_MASK 0xfe000000
#elif BUCKET_SHIFT == 8
	#define BUCKET_MASK 0xff000000
#elif BUCKET_SHIFT == 9
	#define BUCKET_MASK 0xff800000
#elif BUCKET_SHIFT == 10
	#define BUCKET_MASK 0xffc00000
#else 
	#define BUCKET_MASK 0x0 //invalid
#endif

//number of HLL buckets
#define NUM_BUCKETS (2 << (BUCKET_SHIFT - 1))

//use power of 2 size to make the NIC happy
#define MAX_CMS_ELEM 524288

#define NUM_CMS_MAPS 3

#define MAX_CPO_PRGS 5

#define CUSTOM_META_OFFSET 28

#define GPV_HDR_OFFSET 42 // + 42 (eth - 14, ip - 20, udp - 8)


//fds list to control prog monitoring prog execution
struct fd_list_t {
	__u16 fds[MAX_CPO_PRGS];
};

struct hkey_t {
	__u32 saddr;
	__u32 daddr;
	__u16 sport;
	__u16 dport;
	__u8 proto;
	__u8 is_gpv;
};

//metadata added by the smartNIC
struct custom_meta_desc { //28B
	__u32 type;	//enable xdp on host to identify metadata on telemetry packet
	__u32 bucket;
	__u32 num_zeros;
	__u32 hash;
	//__u16 fds[MAX_CPO_PRGS]; //Could not make an array work here because of dynamic memory access on XDP
	
	//only fits 6 fds on headroom if using __u16 for the fds
	//probably Netronome's head room is only a few bytes
	//We may want to confirm Netronome's limits for this
	__u8 total_prgs;
	__u8 fd_prog_ptr;
	__u16 fd_prog1;
	__u16 fd_prog2;
	__u16 fd_prog3;
	__u16 fd_prog4;
	__u16 fd_prog5;
};

struct ip4_5tuple {
	__u32 ip_src;
	__u32 ip_dst;
	__u16 tp_src;
	__u16 tp_dst;
	__u8  ip_proto;
};

struct gpv_pkt_t { //16B
	__u32 ip_src;
	__u32 ip_dst;
	__u16 tp_src;
	__u16 tp_dst;
	__u8 ip_proto;
	__u8 ingress_port;
	__u8 pkt_count;
	__u8 pad;
};

struct gpv_p_t { // 16B
	__u64 timestamp_size;
	__u16 queue_depth;
	__u16 ip_id;
	__u32 pd;
};

struct gpv_pd_tcp_t { // 4B
	__u8 flags;
	__u8 pad[3];
};

struct stats {
	__u64 bytes;
	__u64 pkts;
};

#endif
