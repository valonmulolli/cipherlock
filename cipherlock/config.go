package cipherlock

import "time"

const DefaultChunkSize = 64 * 1024

type FileMeta struct {
	Name    string
	Size    int64
	ModTime time.Time
}

type Profile struct {
	Time     uint32 `json:"time"`
	Memory   uint32 `json:"memory"`
	Threads  uint8  `json:"threads"`
	Checksum bool   `json:"checksum"`
}

type Config struct {
	SaltLen   int
	Time      uint32
	Memory    uint32
	Threads   uint8
	KeyLen    uint32
	Checksum  bool
	ChunkSize int
	FileMeta  *FileMeta
}

func (c *Config) ApplyProfile(p *Profile) {
	if p == nil {
		return
	}
	if p.Time != 0 {
		c.Time = p.Time
	}
	if p.Memory != 0 {
		c.Memory = p.Memory
	}
	if p.Threads != 0 {
		c.Threads = p.Threads
	}
	c.Checksum = p.Checksum
}

var DefaultConfig = &Config{
	SaltLen:   16,
	Time:      3,
	Memory:    64 * 1024,
	Threads:   4,
	KeyLen:    32,
	ChunkSize: DefaultChunkSize,
}
