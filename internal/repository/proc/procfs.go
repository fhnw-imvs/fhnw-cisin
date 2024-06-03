package procrepository

import (
	"fmt"
	"strconv"

	"github.com/prometheus/procfs"
	"gitlab.fhnw.ch/cloud/mse-cloud/cisin/internal/constant"
)

type procFS struct {
	fs procfs.FS
}

func NewProcFS() (Proc, error) {
	fileSystem, err := procfs.NewFS("/proc")
	if err != nil {
		return nil, fmt.Errorf("create proc fs: %w", err)
	}

	return procFS{
		fs: fileSystem,
	}, nil
}

func (p procFS) GetPIDFromPort(port int) (int, error) {
	netTCP, err := p.fs.NetTCP()
	if err != nil {
		return -1, fmt.Errorf("read tcp: %w", err)
	}

	procs, err := p.fs.AllProcs()
	if err != nil {
		return -1, fmt.Errorf("list procs: %w", err)
	}

	for _, line := range netTCP {
		for _, proc := range procs {
			if line.LocalPort != uint64(port) {
				continue
			}

			_, err := proc.FDInfo(strconv.FormatUint(line.Inode, 10))
			if err != nil {
				continue
			}

			return proc.PID, nil
		}
	}

	return -1, constant.ErrNotFound
}
