package exporter

import (
	"log"

	"github.com/ZhangYet/ebpf_exporter/config"
	"github.com/aquasecurity/libbpfgo"
)

func attachModule(module *libbpfgo.Module, cfg config.Config) (map[*libbpfgo.BPFProg]*libbpfgo.BPFLink, error) {
	attached := map[*libbpfgo.BPFProg]*libbpfgo.BPFLink{}

	iter := module.Iterator()
	for {
		prog := iter.NextProgram()
		if prog == nil {
			break
		}

		link, err := prog.AttachGeneric()
		if err != nil {
			log.Printf("Failed to attach program %q for config %q: %v", prog.Name(), cfg.Name, err)
			attached[prog] = nil
		} else {
			attached[prog] = link
		}
	}

	return attached, nil
}
