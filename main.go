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
		"gtp5g_encap_recv",
		"gtp5g_xmit_skb_ipv4",
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
