package cipherlock

const DefaultChunkSize = 64 * 1024

type Config struct {
	SaltLen   int
	Time      uint32
	Memory    uint32
	Threads   uint8
	KeyLen    uint32
	Checksum  bool
	ChunkSize int
}

var DefaultConfig = &Config{
	SaltLen:   16,
	Time:      3,
	Memory:    64 * 1024,
	Threads:   4,
	KeyLen:    32,
	ChunkSize: DefaultChunkSize,
}
