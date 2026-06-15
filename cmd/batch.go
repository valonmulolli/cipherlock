package cmd

import (
	"context"
	"fmt"
	"os"

	"golang.org/x/sync/errgroup"

	"github.com/valonmulolli/cipherlock/cipherlock"
)

type fileJob struct {
	src  string
	dest string
	info os.FileInfo
}

type fileResult struct {
	src  string
	dest string
	err  error
}

func processFilesInParallel(args []string, destFn func(src string, info os.FileInfo) (string, error), processFn func(job fileJob) error, jobs int) error {
	if jobs <= 0 {
		jobs = 1
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	g, _ := errgroup.WithContext(ctx)
	jobsCh := make(chan fileJob, len(args))
	resultsCh := make(chan fileResult, len(args))

	for range jobs {
		g.Go(func() error {
			for job := range jobsCh {
				select {
				case <-ctx.Done():
					return ctx.Err()
				default:
				}

				err := processFn(job)
				select {
				case <-ctx.Done():
					return ctx.Err()
				case resultsCh <- fileResult{src: job.src, dest: job.dest, err: err}:
				}
			}
			return nil
		})
	}

	g.Go(func() error {
		defer close(jobsCh)

		for _, src := range args {
			info, err := os.Stat(src)
			if err != nil {
				return err
			}
			if info.IsDir() {
				return fmt.Errorf("cannot mix files and directories: %s", src)
			}

			dest, err := destFn(src, info)
			if err != nil {
				return err
			}

			select {
			case <-ctx.Done():
				return ctx.Err()
			case jobsCh <- fileJob{src: src, dest: dest, info: info}:
			}
		}
		return nil
	})

	go func() {
		g.Wait()
		close(resultsCh)
	}()

	var firstErr error
	for res := range resultsCh {
		if res.err != nil && firstErr == nil {
			firstErr = res.err
			cancel()
		}
	}

	if firstErr != nil {
		return firstErr
	}

	return g.Wait()
}

func batchEncryptFunc(passwords [][]byte, asymmetricRecipients []*cipherlock.X25519Recipient, config *cipherlock.Config) func(job fileJob) error {
	return func(job fileJob) error {
		return encryptFile(job.src, job.dest, job.info, passwords, asymmetricRecipients, config)
	}
}

func batchDecryptFunc(password []byte, identity *cipherlock.X25519Identity) func(job fileJob) error {
	return func(job fileJob) error {
		if identity != nil {
			return decryptAsymmetricFile(job.dest, job.src, job.info, identity)
		}
		info := job.info

		if checkOnly {
			return checkDecrypt(job.src, info, password)
		}

		if decryptDirMode {
			err := decryptDirSource(job.src, info, password)
			return err
		}

		dest := job.dest
		if !forceOverwrite && !inPlace {
			if _, err := os.Stat(dest); err == nil {
				return fmt.Errorf("output %q exists; use --force to overwrite", dest)
			}
		}

		return decryptFile(job.src, dest, info, password)
	}
}
