#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <chrono>
#include <csignal>
#include <cstdlib>
#include <iostream>
#include <net/if.h>
#include <thread>

#include "xdp_comp_off_user.h"
#include "../shared.h"

static int iface_index = 0;
static uint32_t xdp_flags_host = XDP_FLAGS_DRV_MODE;
int stop = 0;

static void unload_prog(int sig) {
	util::attach_xdp_fd(iface_index, -1, xdp_flags_host);
	std::cout << "unloading xdp program..." << std::endl;
	stop = 1;
}

int main(int argc, char** argv) {

	signal(SIGINT, unload_prog);
	signal(SIGTERM, unload_prog);

	int prog_fd = 0;
	struct bpf_object* bpf_obj = nullptr;
	struct bpf_object* bpf_obj_app = nullptr;

	int cms_map_fds[NUM_CMS_MAPS];
	char cms_map_name[16];
	
	iface_index = if_nametoindex("enp4s0np0np0");

	util::load_xdp_prog("build/bpf/xdp_comp_no_off_kern.o", &bpf_obj, &prog_fd, iface_index, xdp_flags_host);	
	util::attach_xdp_fd(iface_index, prog_fd, xdp_flags_host);

	auto do_gpv_telemetry_map_fd = util::find_map_fd(bpf_obj, "do_telemetry_map");

	auto counter_map_fd = util::find_map_fd(bpf_obj, "counter_map");
	xdp_traffic_counter traffic_counter(counter_map_fd);

	xdp_set_gpv_telemetry xdp_set_gpv_telemetry(do_gpv_telemetry_map_fd);

	for (int i = 0; i < NUM_CMS_MAPS; i++) {
		sprintf(cms_map_name, "map_cms_%i", (i + 1) );
		cms_map_fds[i] = util::find_map_fd(bpf_obj, cms_map_name);
	}

	//configure routing as in Oliver's diagram
	auto xdp_router_map_fd = util::find_map_fd(bpf_obj, "rtg_table_map");
	xdp_router xdp_router(xdp_router_map_fd, bpf_obj);
	util::load_xdp_prog("build/bpf/xdp_loop_analyzer_kern.o", &bpf_obj_app, &prog_fd, iface_index, xdp_flags_host);
	auto loop_analyzer_idx = xdp_router.add_prog_to_map("loop_analyzer", bpf_obj_app);
	struct bpf_object* bpf_obj_app2 = nullptr;
	util::load_xdp_prog("build/bpf/xdp_syn_flood_analyzer_kern.o", &bpf_obj_app2, &prog_fd, iface_index, xdp_flags_host);
	auto syn_flood_analyzer_idx = xdp_router.add_prog_to_map("syn_flood_analyzer", bpf_obj_app2);
	struct bpf_object* bpf_obj_app3 = nullptr;
	util::load_xdp_prog("build/bpf/xdp_traffic_accounting_kern.o", &bpf_obj_app3, &prog_fd, iface_index, xdp_flags_host);
	auto traffic_accounting_idx = xdp_router.add_prog_to_map("traffic_accounting", bpf_obj_app3);

	struct fd_list_t fd_list;
	
	struct hkey_t hkey_conf_rtg;
	hkey_conf_rtg = {0};

	//not setting a key for "match all table"
	fd_list.fds[0] = loop_analyzer_idx;
	xdp_router.update_routing("mt_all_map", hkey_conf_rtg, fd_list);
	fd_list.fds[0] = syn_flood_analyzer_idx;
	hkey_conf_rtg.proto = 6;
	xdp_router.update_routing("mt_proto_map", hkey_conf_rtg, fd_list);

	fd_list.fds[0] = traffic_accounting_idx;
	hkey_conf_rtg.daddr = 167837953; //10.1.1.1
	xdp_router.update_routing("mt_dstip_map", hkey_conf_rtg, fd_list);

	//HyperLogLog
	auto hll_map_fd  = util::find_map_fd(bpf_obj, "map_hll_1");
	xdp_hll xdp_hll(hll_map_fd);

	//Count-min sketch
	xdp_cms xdp_cms(cms_map_fds);
	
		
	/*
	 * Select a key of interest for monitoring
	 * Currently we may set hkey.proto alone 
	 * to monitor UDP or TCP, or we may set the 
	 * whole 5-tuple. We should improve this mechanism
	 * to allow more key options
	 */
	struct hkey_t set_tmt_hkey;
	set_tmt_hkey = { 0 };	

	//set_tmt_hkey.saddr = 167837963; //10.1.1.11
	//set_tmt_hkey.daddr = 167837953; //10.1.1.1
	//set_tmt_hkey.sport = 2048;
	//set_tmt_hkey.dport = 2048;
	//set_tmt_hkey.proto = 17;
	set_tmt_hkey.proto = 6;

	xdp_set_gpv_telemetry.add_source(set_tmt_hkey);

	set_tmt_hkey.proto = 17;

	xdp_set_gpv_telemetry.add_source(set_tmt_hkey);	

	//set a search key to test CMS
	struct hkey_t cms_search_hkey;
	cms_search_hkey = { 0 };	

	cms_search_hkey.saddr = 167837963; //10.1.1.11
	cms_search_hkey.daddr = 167837953; //10.1.1.1
	cms_search_hkey.sport = 2048;
	cms_search_hkey.dport = 2048;
	cms_search_hkey.proto = 17;
	//cms_search_hkey.proto = 6;

	//query the traffic counter (total or per protocol) 
	
	std::uint32_t key;

	while (!stop) {
		std::cout << "--------------------" << std::endl;
		xdp_hll.print_estimate();

		std::cout << "--" << std::endl;
		std::cout << "CMS stats (hkey of interest)" << std::endl;
		xdp_cms.print_cms(cms_search_hkey);

		key = 0;
		std::cout << "--" << std::endl;
		std::cout << "Total" << std::endl;
		traffic_counter.print_stats(key);

		key = 1;
		std::cout << "--" << std::endl;
		std::cout << "Total (TCP)" << std::endl;
		traffic_counter.print_stats(key);

		key = 2;
		std::cout << "--" << std::endl;
		std::cout << "Total (UDP)" << std::endl;
		traffic_counter.print_stats(key);
	
		std::this_thread::sleep_for(std::chrono::milliseconds(1000));
	}

	xdp_router.unpin_app_maps();


	return 0;
}