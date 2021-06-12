
#ifndef XDP_COMP_OFF_USER_H
#define XDP_COMP_OFF_USER_H

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <cstdlib>
#include <stdexcept>
#include <math.h>
#include <string.h>
#include "../bpf/jhash.h"
#include "../shared.h"
#include "util.h"

#define POW_2_32 4294967296 // 2^32
#define NEG_POW_2_32 -4294967296 // -(2^32)

class xdp_set_gpv_telemetry {
public:
	explicit xdp_set_gpv_telemetry(int map_fd) {

		if (map_fd < 0)
			throw std::invalid_argument("xdp_traffic_counter: invalid file descriptor");
		else
			_map_fd = map_fd;
	}

	int add_source(struct hkey_t hkey)
	{
		uint8_t do_telemetry_bm = 1; //bitmap to set telemetry type e.g., GPV or vanilla packets

		print_telemetry_source(hkey);

		if ((bpf_map_update_elem(_map_fd, &hkey, &do_telemetry_bm, BPF_ANY)) != 0)
			throw std::runtime_error("xdp_set_gpv_telemetry: failed reading bpf map contents");

		return 1;
	}

private:
	int _map_fd;

	void print_telemetry_source(struct hkey_t hkey)
	{
		std::cout << "Adding telemetry source: ";
		std::cout << "proto " << hkey.proto << ", ";
		std::cout << "saddr " << hkey.saddr << ", ";
		std::cout << "sport " << hkey.sport << " -> ";
		std::cout << "daddr " << hkey.daddr << ", ";
		std::cout << "dport " << hkey.dport;
		std::cout << std::endl;
	}
};

/** HyperLogLog Cardinality Estimator
 *
 * described in Philippe Flajolet, Éric Fusy, Olivier Gandouet, Frédéric Meunier. HyperLogLog: the analysis of a
 * near-optimal cardinality estimation algorithm. AofA: Analysis of Algorithms, Jun 2007, Juan les Pins, France.
 * pp.137-156. hal-00406166v2 (https://hal.inria.fr/hal-00406166v2)
 */

class xdp_hll {
public:
	explicit xdp_hll(int map_fd) 
	{
		if (map_fd < 0)
			throw std::invalid_argument("xdp_hll: invalid file descriptor");
		else
			_map_fd = map_fd;

		//init M
		for (int i = 0; i < NUM_BUCKETS; i++)
			M[i] = 0;
	}

	double estimate()
	{
		double E;
		for (int bucket = 0; bucket < NUM_BUCKETS; bucket++) {
			ret = bpf_map_lookup_elem(_map_fd, &bucket, &num_zeros);

			if (ret == 0)
			{
				M[bucket] = num_zeros;
			}
		}
		E = _estimate(M, b);

		return E;
	}

	void print_estimate()
	{
		std::cout << "Distinct flows (HLL estimate): " << estimate() << std::endl;
	}


private:
	int _map_fd;
	int num_zeros;
	int ret;
	double E; //estimate
	int M[NUM_BUCKETS];
	int b = log2(NUM_BUCKETS);

	double _estimate(int *M, int b)
	{
		double alpha;

    	switch(b) {
            case 4: alpha = 0.673;
            case 5: alpha = 0.697;
            case 6: alpha = 0.709;
            default: alpha = 0.7213 / (1.0 + 1.079 / (1 << b));
    	}

    	double E = alpha * NUM_BUCKETS * NUM_BUCKETS * indicator(M); // raw estimate

    	if (E <= 2.5 * NUM_BUCKETS) {
        	int zero_registers = count_zero_registers(M);
        	if (zero_registers > 0) {
            	// linear counting:
            	E = NUM_BUCKETS * log10((double)NUM_BUCKETS / zero_registers);
        	}
        	else if (E > (1.0 / 30.0) * POW_2_32){
            	E = NEG_POW_2_32 * log10(1.0 - (E / POW_2_32));
        	}
    	}
    return E;
	}

	double indicator(int *M)
	{
    	double sum = 0.0;

    	for(int i = 0; i < NUM_BUCKETS; i++)
        	sum += 1.0 / (1 << M[i]);

    	return 1 / sum;
	}

	int count_zero_registers(int *M)
	{
    	int zero_registers = 0;

    	for(int i = 0; i < NUM_BUCKETS; i++){
        	if(M[i] == 0)
            	zero_registers++;
    	}

    	return zero_registers;
	}
};

class xdp_traffic_counter {

public:

	explicit xdp_traffic_counter(int map_fd) {

		if (map_fd < 0)
			throw std::invalid_argument("xdp_traffic_counter: invalid file descriptor");
		else
			_map_fd = map_fd;
	}

	struct stats stats(std::uint32_t key) const {

		struct stats total = { .bytes = 0, .pkts = 0 };

		if ((bpf_map_lookup_elem(_map_fd, &key, &total)) != 0)
			throw std::runtime_error("xdp_traffic_counter: failed reading bpf map contents");

		return total;
	}

	void print_stats(std::uint32_t key) const {
		struct stats stat = stats(key);
		std::cout << "byte count: " << stat.bytes << std::endl;
		std::cout << "pkt count: " << stat.pkts << std::endl;
	}

private:
	int _map_fd;
};

//currently we support per-flow pkt and byte counts
//cms should be queried with a known 5-tuple key (struct hkey_t)
class xdp_cms {

public:

	explicit xdp_cms(int map_fd[]) {
		for (int i = 0; i < NUM_CMS_MAPS; i++){
			if (map_fd < 0)
				throw std::invalid_argument("xdp_cms: invalid file descriptor");
			else
				_map_fd[i] = map_fd[i];
		}
	}

	struct stats get_stats(struct hkey_t hkey) const {
		struct stats stat = {0};
		stat.pkts = get_cms_pkt_count(hkey);
		stat.bytes = get_cms_byte_count(hkey);

		return stat;
	}

	void print_cms(struct hkey_t hkey) const {
		struct stats stat = {0};
		stat.pkts = get_cms_pkt_count(hkey);
		stat.bytes = get_cms_byte_count(hkey);
		std::cout << "byte count: " << stat.bytes << std::endl;
		std::cout << "pkt count: " << stat.pkts << std::endl;
	}

private:
	int _map_fd[NUM_CMS_MAPS];

	std::uint64_t get_cms_pkt_count(struct hkey_t hkey) const {

		struct stats total[NUM_CMS_MAPS] = {0};
		std::uint64_t pkts;
		std::uint32_t hash; 
		std::uint32_t key;
 

		for (int i = 0; i < NUM_CMS_MAPS; i++){
			hash = jhash(&hkey, sizeof(struct hkey_t), (i + 1) );
			key = hash % MAX_CMS_ELEM;
			if ((bpf_map_lookup_elem(_map_fd[i], &key, &total[i])) != 0)
				throw std::runtime_error("xdp_cms_pkt_count: failed reading bpf map contents");
		}

		pkts = total[0].pkts;

		for (int i = 1; i < NUM_CMS_MAPS; i++){
			if (total[i].pkts < pkts)
				pkts = total[0].pkts;
		}

		return pkts;
	}

	std::uint64_t get_cms_byte_count(struct hkey_t hkey) const {

		struct stats total[3] = {0};
		std::uint64_t bytes;
		std::uint32_t hash; 
		std::uint32_t key;
		
		for (int i = 0; i < NUM_CMS_MAPS; i++){
			hash = jhash(&hkey, sizeof(struct hkey_t), (i + 1));
			key = hash % MAX_CMS_ELEM;
			if ((bpf_map_lookup_elem(_map_fd[i], &key, &total[i])) != 0)
				throw std::runtime_error("xdp_cms_byte_count: failed reading bpf map contents");
		}

		bytes = total[0].bytes;

		for (int i = 1; i < NUM_CMS_MAPS; i++){
			if (total[i].bytes < bytes)
				bytes = total[0].bytes;
		}

		return bytes;
	}
};

class xdp_router {
public:
	//the map lookup here may be hard coded
	explicit xdp_router(int map_fd, struct bpf_object* bpf_obj) {

		if (map_fd < 0)
			throw std::invalid_argument("xdp_router: invalid file descriptor");
		else
			_map_fd = map_fd;

		if (bpf_obj == nullptr)
			throw std::invalid_argument("xdp_router: invalid bpf object");
		else
			_bpf_obj = bpf_obj;

		_bpf_prog = bpf_object__find_program_by_name(bpf_obj, "xdp_route_pkt");
		_xdp_route_pkt_fd = bpf_program__fd(_bpf_prog);

		init_ind_table(bpf_obj);

		_idx = 0;

	}

	int add_prog_to_map(const char *prog_name, struct bpf_object* bpf_obj)
	{
		_bpf_prog = bpf_object__find_program_by_name(bpf_obj, prog_name);
		int prog_fd = bpf_program__fd(_bpf_prog);
		int cur_idx = _idx;
		if ((bpf_map_update_elem(_map_fd, &cur_idx, &prog_fd, 0)) != 0)
			throw std::runtime_error("xdp_router: failed adding program to map");

		init_ind_table(bpf_obj);

		pin_app_maps(bpf_obj);

		_idx++;
		return cur_idx;
	}

	void update_routing(const char *map_name, struct hkey_t hkey, struct fd_list_t fd_list)
	{
		if (!strcmp(map_name, "mt_all_map"))
		{
			__u8 key = 0;

			auto map_fd  = util::find_map_fd(_bpf_obj, map_name);
			
			if ((bpf_map_update_elem(map_fd, &key, &fd_list, 0)) != 0)
				throw std::runtime_error("xdp_router: failed adding program to map");
		}

		else if (!strcmp(map_name, "mt_proto_map"))
		{
			__u16 key = hkey.proto;

			auto map_fd  = util::find_map_fd(_bpf_obj, map_name);
			
			if ((bpf_map_update_elem(map_fd, &key, &fd_list, 0)) != 0)
				throw std::runtime_error("xdp_router: failed adding program to map");
		}

		else if (!strcmp(map_name, "mt_dstip_map"))
		{
			__u32 key = hkey.daddr;

			auto map_fd  = util::find_map_fd(_bpf_obj, map_name);
			
			if ((bpf_map_update_elem(map_fd, &key, &fd_list, 0)) != 0)
				throw std::runtime_error("xdp_router: failed adding program to map");
		}

		else
			throw std::runtime_error("xdp_router: invalid map");

	}

	void pin_app_maps(struct bpf_object* bpf_obj)
	{
		_bpf_obj_apps[_idx] = bpf_obj;

		bpf_object__pin_maps(bpf_obj, "/sys/fs/bpf/");
		//avoid conflicts between rtg_ind_table_map from different apps
		std::remove("/sys/fs/bpf/rtg_ind_table_map");
		
	}

	void unpin_app_maps(void)
	{
		std::cout << "unpinning maps" << std::endl;
		system("rm /sys/fs/bpf/xdp_*_map");
	}

private:
	int _map_fd;
	int _idx;
	int _xdp_route_pkt_fd;
	struct bpf_object *_bpf_obj = nullptr;
	struct bpf_program *_bpf_prog;
	struct bpf_object *_bpf_obj_apps[MAX_CPO_PRGS];


	void init_ind_table(struct bpf_object* bpf_obj)
	{

		int entry_idx = 0;
		auto rtg_ind_table_map_fd = util::find_map_fd(bpf_obj, "rtg_ind_table_map");
		if ((bpf_map_update_elem(rtg_ind_table_map_fd, &entry_idx, &_xdp_route_pkt_fd, 0)) != 0)
			throw std::runtime_error("xdp_router: failed initing rtg_ind_table_map");

	}

};

#endif
