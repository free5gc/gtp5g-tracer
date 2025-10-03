package main

import (
	"os"
	"time"

	bpf "github.com/aquasecurity/libbpfgo"
)

func main() {
	bpfModule, err := bpf.NewModuleFromFile("gtp5g_tracer_kern.o")
	if err != nil {
		panic(err)
	}
	defer bpfModule.Close()

	if err := bpfModule.BPFLoadObject(); err != nil {
		panic(err)
	}

	var progNameList = []string{
		// Original tracing points
		"gtp5g_encap_recv_entry",
		"gtp5g_encap_recv_exit",
		"gtp5g_xmit_skb_ipv4_entry",
		"gtp5g_xmit_skb_ipv4_exit",
		
		// Additional packet handling functions
		"gtp5g_handle_skb_ipv4_entry",
		"gtp5g_handle_skb_ipv4_exit",
		"gtp5g_push_header_entry",
		"gtp5g_push_header_exit",
		
		// PDR matching functions
		"pdr_find_by_gtp1u_entry",
		"pdr_find_by_gtp1u_exit",
		
		// QoS enforcement
		"policePacket_entry",
		
		// IP routing function
		"ip4_find_route_entry",
		"ip4_find_route_exit",
	}

	for _, progName := range progNameList {
		prog, err := bpfModule.GetProgram(progName)
		if err != nil {
			panic(err)
		}
		link, err := prog.AttachGeneric()
		if err != nil {
			panic(err)
		}
		if link.FileDescriptor() == 0 {
			os.Exit(-1)
		}
	}

	for {
		time.Sleep(10 * time.Second)
	}
}
