# Faster Software Packet Processing on FPGA NICs with eBPF Program Warping

## Artifacts evaluation instructions

## Repository structure

The repository is structured as follows:
- *ubpf/* contains the eBPF/hXDP emulator software written in C, along with some utilities to generate the eBPF maps configuration and the program encoding
- *use_cases/* comprises all the files needed to execute the use cases described in the paper. Moreover, inside each use case directory, there is a *.gen/* directory which contains all the files ready to get the use case running in the simulator
- *warp_compiler.sh* is a script to connect to the remote instance of the Warp compiler

## Workflow

In this section, we describe the workflow from an eBPF program written in C to the execution with the uBPF emulator.

1. Compile the original program with the standard Linux eBPF LLVM compiler. For convenience, for each use case, we provide an already compiled *.o* object of the program.
2. The *.o* object is provided to the hXDP Warp Compiler, obtaining the match-action table configuration encoded in JSON format
3. To execute the program in the simulator, we must apply some preprocessing to the *.o* eBPF program: (i) to extract the MAP information contained in the ELF file and export it in JSON format; (ii) to output the instructions contained in the ELF in a format readable by the uBPF emulator. There is a python script which performs these tasks.
4. We can now run the *vanilla* eBPF program, i.e. without the warp engine. The emulator takes as input the files described before (maps description and program) and the pcap trace, specifically constructed to trigger all the processing branches. The program outputs the execution information like the number of instructions executed and the pcap traces containing the processed packets.
5. At last, we run the same eBPF program with the Warp Engine turned on, i.e. with the match-action table and the context restoration functions. The emulator takes the same inputs as in 4, plus the match-action table JSON file obtained from point 2. The program outputs the same execution information, and the number of the entry matched in the match-action table. 


We can obtain the speedup in terms of number of executed instructions by comparing the emulator outputs of the vanilla and "warped" executions.

## 1. Compile an eBPF program

Different use cases compile differently: there are custom use cases implemented from the [xdp-tutorial](https://github.com/xdp-project/xdp-tutorial) repository (L2 ACL and DNAT), use-cases taken from the Linux kernel (Router and Tunnel), and two open-source projects (Katran and Suricata). For each use case, we provide (and suggest to use) the already LLVM compiled program, since compiling the use cases can be time consuming given the requirements and compatibility issues between OS versions. 
### L2 ACL and DNAT
Clone the [xdp-tutorial](https://github.com/xdp-project/xdp-tutorial). Copy the two folders ‘l2acl’ and ‘dnat’ inside the xdp-tutorial folder. Now follow the xdp-tutorial repository README to compile the use-cases.

### Linux Kernel BPF examples
The two use-cases can be found in the Linux kernel source tree (for the paper we used the 5.4 kernel version): the router in samples/bpf/xdp_router_ipv4_kern.c, and the tunnel in samples/bpf/xdp_tx_iptunnel_kern.c. For the compilation of these use-cases follow the official Linux kernel documentation.

### KATRAN and SURICATA
The [Katran](https://github.com/facebookincubator/katran) and [Suricata](https://github.com/OISF/suricata) use cases can be compiled following the instructions of their original repositories. Although, we suggest to use the already compiles object contained in the *use_cases* folder.

## 2. Warp Compile to obtain the MAT

The warp compiler is deployed as a service reachable at xxxx:3200. By sending the LLVM compiled .o file and the program main section name, it responds with the MAT and context restorator configuration of the program. The compiler can be reached with the script ‘compile.sh’:

	$ sudo chmod +x warp_compiler.sh
	$ ./warp_compiler.sh <program.o> <secname>

The MAT and context restorator configuration are saved in the file named <program.o>.json.

| Use-case | Object file name | Section name |
|----------|------------------|--------------|
| L2ACL | l2acl.o | xdp |
| Router | xdp_router_ipv4_kern.o | xdp_router_ipv4 |
| Tunnel | xdp_tx_iptunnel_kern.o | xdp_tx_iptunnel |
| DNAT | dnat.o | xdp |
| Suricata | xdp_filter.o | xdp |
| Katran | balancer_kern.o | xdp-balancer |


## 3. eBPF program preprocessing

### Build the simulator

#### Requirements
In the *ubpf/* folder, issue the following commands:

	$ sudo apt-get update
	$ sudo apt-get -y install python3 python3-pip libpcap-dev
	$ pip3 install -r requirements.txt

#### Build

To build the simulator, it is sufficient to issue the following command from within the ubpf directory:

	$ make -C vm

It produces an executable in the *vm/* folder called __"hXDP_sim"__. 

### Generate the files needed by the simulator

The script responsible for the preprocessing of eBPF maps and programs is *"readelf.py"* contained in the *ubpf* directory. It produces two files:

- a *"usecase.bin"* file, which contains the hexadecimal representation of the program instructions
- a *"usecase_maps.json"* file, which contains a JSON representation of the maps employed in the program

Execute the python script with these parameters:

	$ python3 readelf.py <filename.o> <usecase-name> <secname>

- *filename.o* is the ELF object containing the LLVM compiled program
- *usecase-name* is the name used for the output files (*usecase.bin* and *usecase_maps.json*, written in the working directory)
- *secname* is the section name used in the XDP program (usually *xdp*, can be found in the main function of the C source code of the use case)

## 4. Execute the *vanilla* use case

To execute a program in the simulator without the match-action table, the basic command is the following:

	$ ./hXDP_sim --maps usecase_maps.json --pcap usecase.pcap -e usecase_map_entries.json -l 1 usecase.bin

- *usecase_maps.json* and *usecase.bin* are the files generated by the *readelf.py* script
- *usecase.pcap* is the pcap trace that provides the packets for the specific use case
- *usecase_map_entries.json* is needed to populate the map entries
- *-l 1* sets the log level. 1 for basic information, 3 for extended logs (prints the context for each instruction)

As an example, we can run the *l2 acl* use case as follows:

	$ ./vm/hXDP_sim --maps use_cases/l2_acl/l2acl_maps.json --pcap use_cases/l2_acl/l2acl.pcap -e use_cases/l2_acl/l2acl_map_entries.json -l 1 use_cases/l2_acl/l2acl.bin


which produces this output:

	hXDP_sim.c:514: info: In function main: Packet #1
	ubpf_vm.c:783: info: In function ubpf_exec: Instructions count: 15
	hXDP_sim.c:567: info: In function main: return 0x1
	
	hXDP_sim.c:514: info: In function main: Packet #2
	ubpf_vm.c:783: info: In function ubpf_exec: Instructions count: 40
	hXDP_sim.c:567: info: In function main: return 0x2
	
	hXDP_sim.c:514: info: In function main: Packet #3
	ubpf_vm.c:783: info: In function ubpf_exec: Instructions count: 17
	hXDP_sim.c:567: info: In function main: return 0x2
	
	hXDP_sim.c:514: info: In function main: Packet #4
	ubpf_vm.c:783: info: In function ubpf_exec: Instructions count: 39
	hXDP_sim.c:567: info: In function main: return 0x1

This log displays the number of the processed packet, the number of instructions executed and the return code of the XDP program (i.e. XDP_ABORTED=0, XDP_DROP=1, XDP_PASS=2, XDP_TX=3)

To export the processed packets in pcap traces, add the *-O* option to the command line arguments. It will produce four different traces in which the processed packets are grouped by return code.

## 5. Execute the *warped* use case

To execute the same program with the Warp Engine, just provide the match-action table JSON file to the command line arguments:

	$ ./hXDP_sim --mat usecase_mat.json ...

For example, for the l2acl use case:

	$ ./vm/hXDP_sim --mat use_cases/l2_acl/l2acl_mat.json --maps use_cases/l2_acl/l2acl_maps.json --pcap use_cases/l2_acl/l2acl.pcap -e use_cases/l2_acl/l2acl_map_entries.json -l 1 use_cases/l2_acl/l2acl.bin

which produces the following output:

	hXDP_sim.c:514: info: In function main: Packet #1
	match_unit.c:584: info: In function lookup_entry: Matched entry number: 0
	hXDP_sim.c:529: warning: In function main: Instructions count: 0
	hXDP_sim.c:567: info: In function main: return 0x1
	
	hXDP_sim.c:514: info: In function main: Packet #2
	match_unit.c:584: info: In function lookup_entry: Matched entry number: 1
	ubpf_vm.c:783: info: In function ubpf_exec: Instructions count: 6
	hXDP_sim.c:567: info: In function main: return 0x2
	
	hXDP_sim.c:514: info: In function main: Packet #3
	match_unit.c:584: info: In function lookup_entry: Matched entry number: 2
	hXDP_sim.c:529: warning: In function main: Instructions count: 0
	hXDP_sim.c:567: info: In function main: return 0x2
	
	hXDP_sim.c:514: info: In function main: Packet #4
	match_unit.c:584: info: In function lookup_entry: Matched entry number: 1
	ubpf_vm.c:783: info: In function ubpf_exec: Instructions count: 5
	hXDP_sim.c:567: info: In function main: return 0x1

We obtain the same information as before, but with the addition of the ID of the entry matched in the match-action table.

The comparison between the "vanilla" and the "warped" number of instructions gives the results displayed in the Figure 5 of the paper. 

## IMPORTANT NOTES!

### Katran

For Katran, it is suggested to use the *katran.bin* and *katran_maps.json* provided (so skipping *readelf.py* step). In fact, to generate "MAP in MAP" table it is necessary to manually write a JSON entry for the inner map, since that information is not contained in the ELF. In the provided maps JSON file, the inner map is already inserted.
