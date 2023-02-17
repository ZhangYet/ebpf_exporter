package exporter

import (
	"fmt"
	"github.com/ZhangYet/ebpf_exporter/config"
	"strconv"
	"strings"
)

const (
	labelPid  = "pid"
	labelType = "type"

	// PerfMap name
	// For these maps, we need to map the values of `type` into flags
	PerfMapExt4IoLatency       = "ext4latency"
	PerfMapExt4IoSize          = "ext4size"
	PerfMapExt4IoNumsOverThres = "ext4nums"
)

var ext4ioTableNames = map[string]bool{
	PerfMapExt4IoLatency:       true,
	PerfMapExt4IoSize:          true,
	PerfMapExt4IoNumsOverThres: true,
}

const (
	EbpfMetricNoType uint32 = iota
	// for ext4io
	EbpfMetricExt4IoRead
	EbpfMetricExt4IoWrite
	EbpfMetricExt4IoOpen
	EbpfMetricExt4IoFsync
)

//      #define TRACE_READ      0
//      #define TRACE_WRITE     1
//      #define TRACE_OPEN      2
//      #define TRACE_FSYNC     3
var ext4IoBpfTypeMap = map[int]uint32{
	0: EbpfMetricExt4IoRead,
	1: EbpfMetricExt4IoWrite,
	2: EbpfMetricExt4IoOpen,
	3: EbpfMetricExt4IoFsync,
}

// Extract information from labels and label values.
// This is business-related logic.
func extractInfoFromLabels(tableName string, labels []config.Label, values []string) (cmd string, pid uint32, typ uint32) {
	tmp := make([]string, len(labels))
	for i, label := range labels {
		tmp[i] = fmt.Sprintf("%s:%s", label.Name, values[i])
		if label.Name == labelPid {
			p, _ := strconv.Atoi(values[i])
			pid = uint32(p)
		}
		if label.Name == labelType {
			if _, ok := ext4ioTableNames[tableName]; !ok {
				continue
			}
			mtype, _ := strconv.Atoi(values[i])
			typ = ext4IoBpfTypeMap[mtype]
		}
	}
	cmd = strings.Join(tmp, "@@")
	return
}

func calPidAndFlag(pid, flag uint32) uint64 {
	return uint64(flag)<<32 + uint64(pid)
}
