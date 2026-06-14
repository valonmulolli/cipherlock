package cmd

import (
	"sync"
	"testing"

	"github.com/valonmulolli/cipherlock/cipherlock"
)

func TestProfileConcurrentSet(t *testing.T) {
	var wg sync.WaitGroup
	errs := make(chan error, 16)

	for i := range 8 {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			name := t.Name()
			store, err := loadProfileStore()
			if err != nil {
				errs <- err
				return
			}
			store.Profiles[name] = cipherlock.Profile{
				Time:     uint32(n + 1),
				Memory:   65536,
				Threads:  1,
				Checksum: true,
			}
			if err := saveProfileStore(store); err != nil {
				errs <- err
				return
			}
		}(i)
	}

	wg.Wait()
	close(errs)

	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
}
