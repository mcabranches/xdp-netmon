
BUILD_DIR = build
BUILD_USER_DIR = $(BUILD_DIR)/user
BUILD_BPF_DIR = $(BUILD_DIR)/bpf
EXT_LIBBPF_DIR = ext/libbpf
EXT_INCLUDE_DIR = ext/include

LLC ?= llc
CLANG ?= clang
CXXFLAGS ?= -Wall -g

#add entries for non-offload versions
all: $(BUILD_USER_DIR)/xdp_comp_off_user $(BUILD_BPF_DIR)/xdp_comp_off_kern_nic.o $(BUILD_BPF_DIR)/xdp_comp_off_kern_host.o \
			$(BUILD_BPF_DIR)/xdp_dns_refl_analyzer_kern.o $(BUILD_BPF_DIR)/xdp_syn_flood_analyzer_kern.o \
			$(BUILD_BPF_DIR)/xdp_traffic_accounting_kern.o $(BUILD_USER_DIR)/xdp_comp_syn_flood_analyzer_user \
			$(BUILD_USER_DIR)/xdp_comp_no_off_user $(BUILD_BPF_DIR)/xdp_comp_no_off_kern.o
			
# directories:

$(BUILD_USER_DIR): $(BUILD_DIR)
	mkdir -p $@

$(BUILD_BPF_DIR): $(BUILD_DIR)
	mkdir -p $@

$(BUILD_DIR):
	mkdir -p $@

# libbpf:

$(EXT_LIBBPF_DIR)/src/libbpf.a:
	cd $(EXT_LIBBPF_DIR)/src && $(MAKE) all OBJDIR=.; \
	mkdir -p build; $(MAKE) install_headers DESTDIR=build OBJDIR=.; \

# user space programs:

$(BUILD_USER_DIR)/%: $(BUILD_USER_DIR) src/user/%.cc $(EXT_LIBBPF_DIR)/src/libbpf.a src/user/util.h
	$(CXX) $(CXXFLAGS) -I$(EXT_LIBBPF_DIR)/src/build/usr/include -I$(EXT_INCLUDE_DIR) -L$(EXT_LIBBPF_DIR)/src -o$@ $(filter-out $<,$^) -lelf -lz

# kernel programs:

# build clang intermediate representation
$(BUILD_BPF_DIR)/%.ll: $(BUILD_BPF_DIR) src/bpf/%.c
	$(CLANG) -S -target bpf -D __BPF_TRACING__ \
		-I$(EXT_LIBBPF_DIR)/src/build/usr/include/ -I$(EXT_INCLUDE_DIR) \
		-Wall -Wno-unused-value -Wno-pointer-sign -Wno-compare-distinct-pointer-types -Werror \
		-O2 -emit-llvm -c -g -o $@ $(filter-out $<,$^)

# build bpf bytecode
$(BUILD_BPF_DIR)/%.o: $(BUILD_BPF_DIR)/%.ll
	$(LLC) -march=bpf -filetype=obj -o $@ $<

# cleanup:

clean:
	$(RM) -r $(BUILD_DIR)
	$(MAKE) -C $(EXT_LIBBPF_DIR)/src clean
	$(RM) -r $(EXT_LIBBPF_DIR)/src/build

.PHONY: all clean
