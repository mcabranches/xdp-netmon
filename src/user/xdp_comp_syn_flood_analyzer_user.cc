#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <chrono>
#include <csignal>
#include <cstdlib>
#include <iostream>
#include <net/if.h>
#include <thread>


int main(int argc, char** argv) {

    int map_fd;
	int count;
	int key = 0;

    map_fd = bpf_obj_get("/sys/fs/bpf/xdp_syn_flood_analyzer_map");

    while (1) {
	    bpf_map_lookup_elem(map_fd, &key, &count);
	    std::cout << "count: " << count << std::endl;

        //userspace syn flood logic goes here
	
	    std::this_thread::sleep_for(std::chrono::milliseconds(1000));
	}

	return 0;
}
