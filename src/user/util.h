
#ifndef USER_UTIL_H
#define USER_UTIL_H

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/if_link.h>
#include <stdexcept>
#include "../shared.h"
#include <cstdio>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <array>

namespace util {

	static void load_xdp_prog(const char* file_name, struct bpf_object** bpf_obj, int* fd, int ifindex, int xdp_flags) {
		
		struct bpf_prog_load_attr prog_load_attr = {
			.file = file_name,
			.prog_type = BPF_PROG_TYPE_XDP
		};

		if (xdp_flags == XDP_FLAGS_HW_MODE)
			prog_load_attr.ifindex = ifindex; /* set offload dev ifindex */

		if (bpf_prog_load_xattr(&prog_load_attr, bpf_obj, fd))
			throw std::runtime_error("load_xdp_program: cannot load object file");
		
		if (*fd < 1)
			throw std::runtime_error("load_xdp_program: invalid program fd");
	}

	static void attach_xdp_fd(int iface_index, int prog_fd, uint32_t xdp_flags) {
		
		if (bpf_set_link_xdp_fd(iface_index, prog_fd, xdp_flags) < 0)
			throw std::runtime_error("attach_xdp_fd: failed attaching xdp");
	}


	static int find_map_fd(struct bpf_object* bpf_obj, const char* map_name) {
		struct bpf_map* map = bpf_object__find_map_by_name(bpf_obj, map_name);
		
		if (map == nullptr)
			return -1;

		return bpf_map__fd(map);
	}

	std::string exec(const char* cmd) {
    	std::array<char, 128> buffer;
    	std::string result;
    	std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(cmd, "r"), pclose);
    	if (!pipe) {
        	throw std::runtime_error("popen() failed!");
    	}
    	while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
        	result += buffer.data();
    	}
    	return result;
	}
}

#endif
