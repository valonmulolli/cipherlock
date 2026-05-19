package cipherlock

import "time"

const DefaultChunkSize = 64 * 1024

type FileMeta struct {
	Name    string
	Size    int64
	ModTime time.Time
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

var DefaultConfig = &Config{
	SaltLen:   16,
	Time:      3,
	Memory:    64 * 1024,
	Threads:   4,
	KeyLen:    32,
	ChunkSize: DefaultChunkSize,
}
