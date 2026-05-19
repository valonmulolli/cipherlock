package cipherlock

import (
	"archive/tar"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// EncryptDir encrypts a directory by tar+gzipping it and encrypting the archive.
// The result is written to dest (or source+.cipherlock if dest is empty).
func EncryptDir(source, dest string, password []byte, config *Config) error {
	source = strings.TrimRight(source, "/\\")

	if dest == "" {
		dest = source + ".cipherlock"
	}

	pipeR, pipeW := io.Pipe()
	defer pipeR.Close()

	go func() {
		err := tarGzDir(source, pipeW)
		pipeW.CloseWithError(err)
	}()

	destFile, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer destFile.Close()

	return Encrypt(destFile, pipeR, password, config)
}

// DecryptDir decrypts a cipherlock file containing a tar.gz archive and extracts it.
// The output directory defaults to source without the .cipherlock or .encrypted suffix.
func DecryptDir(source, dest string, password []byte) error {
	if dest == "" {
		dest = strings.TrimSuffix(source, ".cipherlock")
		dest = strings.TrimSuffix(dest, ".encrypted")
	}

	pipeR, pipeW := io.Pipe()
	defer pipeR.Close()

	srcFile, err := os.Open(source)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	go func() {
		err := Decrypt(pipeW, srcFile, password)
		pipeW.CloseWithError(err)
	}()

	return untarGzDir(dest, pipeR)
}

func tarGzDir(source string, w io.Writer) error {
	gw := gzip.NewWriter(w)
	tw := tar.NewWriter(gw)

	err := filepath.Walk(source, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		header, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}

		rel, err := filepath.Rel(source, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		header.Name = filepath.ToSlash(rel)

		if err := tw.WriteHeader(header); err != nil {
			return err
		}

		if info.IsDir() {
			return nil
		}

		f, err := os.Open(path)
		if err != nil {
			return err
		}
		_, err = io.Copy(tw, f)
		f.Close()
		return err
	})
	if err != nil {
		gw.Close()
		return err
	}

	if err := tw.Close(); err != nil {
		return err
	}
	return gw.Close()
}

func untarGzDir(dest string, r io.Reader) error {
	gr, err := gzip.NewReader(r)
	if err != nil {
		return err
	}
	defer gr.Close()

	tr := tar.NewReader(gr)

	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		target := filepath.Join(dest, header.Name)

		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0755); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
				return err
			}
			f, err := os.Create(target)
			if err != nil {
				return err
			}
			_, err = io.Copy(f, tr)
			f.Close()
			if err != nil {
				return err
			}
		}
	}

	return nil
}
