package sdk

import (
	"github.com/ZhangYet/ebpf_exporter/config"
	"github.com/ZhangYet/ebpf_exporter/exporter"
	"log"
	"sync"
)

type EbpfExporterWrapper interface {
	QueryRaw() (map[string][]exporter.RawMetric, error)
	Reset()
}

type DefaultExporterWrapper struct {
	exporter *exporter.Exporter
	configs  []config.Config
	mu       sync.Mutex
}

func NewDefaultEbpfExporterWrapper(configDir string, configNames []string) (EbpfExporterWrapper, error) {
	configs, err := config.ParseConfigs(configDir, configNames)
	if err != nil {
		return nil, err
	}
	e, err := exporter.New(configs)
	if err != nil {
		return nil, err
	}
	if err := e.Attach(); err != nil {
		return nil, err
	}
	e.DescribeWrap()
	return &DefaultExporterWrapper{exporter: e, configs: configs}, nil
}

func (r *DefaultExporterWrapper) Reset() {
	oldExporter := r.exporter
	defer oldExporter.Reclaim()
	e, err := exporter.New(r.configs)
	if err != nil {
		log.Printf("Reset exporter err [New]: %v", err)
		return
	}
	if err := e.Attach(); err != nil {
		log.Printf("Reset exporter err [Attach]: %v", err)
		return
	}
	e.DescribeWrap()
	r.mu.Lock()
	defer r.mu.Unlock()
	r.exporter = e
}

func (r *DefaultExporterWrapper) QueryRaw() (map[string][]exporter.RawMetric, error) {
	return r.exporter.CollectRaw()
}
