package cipherlock

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
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
	defer pipeR.Close() //nolint:errcheck

	go func() {
		err := tarGzDir(source, pipeW)
		pipeW.CloseWithError(err)
	}()

	destFile, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer destFile.Close() //nolint:errcheck

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
	defer pipeR.Close() //nolint:errcheck

	srcFile, err := os.Open(source)
	if err != nil {
		return err
	}
	defer srcFile.Close() //nolint:errcheck

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
		f.Close() //nolint:errcheck
		return err
	})
	if err != nil {
		gw.Close() //nolint:errcheck
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
	defer gr.Close() //nolint:errcheck

	tr := tar.NewReader(gr)

	// Resolve dest to an absolute, symlink-free path so we can check that every
	// extracted entry stays inside it. This blocks tar-slip attacks where a
	// header.Name of "../../etc/passwd" or an absolute path tries to write
	// outside the destination directory.
	destAbs, err := filepath.Abs(dest)
	if err != nil {
		return err
	}
	// EvalSymlinks returns "" on error; preserve the absolute path so the
	// containment check below still works when dest does not exist yet.
	resolved, err := filepath.EvalSymlinks(destAbs)
	if err != nil {
		resolved = destAbs
	}
	destAbs = resolved

	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		// Reject absolute paths and any path that, after cleaning, escapes dest.
		// We construct the candidate, then resolve symlinks on the parent path
		// (the leaf may not exist yet) and re-verify containment.
		cleaned := filepath.Clean(header.Name)
		if filepath.IsAbs(cleaned) || startsWithDotDot(cleaned) {
			return fmt.Errorf("cipherlock: refusing unsafe path %q", header.Name)
		}
		target := filepath.Join(destAbs, cleaned)

		parent := filepath.Dir(target)
		resolvedParent, evalErr := filepath.EvalSymlinks(parent)
		if evalErr != nil {
			// Parent may not exist yet; fall back to a path that is provably
			// inside destAbs (parent is built from destAbs + cleaned).
			resolvedParent = parent
		}
		if !pathHasPrefix(resolvedParent, destAbs) {
			return fmt.Errorf("cipherlock: refusing path %q outside destination", header.Name)
		}

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
			f.Close() //nolint:errcheck
			if err != nil {
				return err
			}
		case tar.TypeSymlink:
			linkTarget := header.Linkname
			if filepath.IsAbs(linkTarget) {
				cleanedLink := filepath.Clean(linkTarget)
				if !pathHasPrefix(cleanedLink, destAbs) {
					return fmt.Errorf("cipherlock: refusing symlink %q -> %q outside destination", header.Name, linkTarget)
				}
			} else {
				resolvedTarget := filepath.Clean(filepath.Join(filepath.Dir(target), linkTarget))
				if !pathHasPrefix(resolvedTarget, destAbs) {
					return fmt.Errorf("cipherlock: refusing symlink %q -> %q outside destination", header.Name, linkTarget)
				}
			}
			if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
				return err
			}
			if err := os.Symlink(linkTarget, target); err != nil {
				return err
			}
		case tar.TypeLink:
			linkTarget := filepath.Join(destAbs, header.Linkname)
			cleanedLink := filepath.Clean(linkTarget)
			if !pathHasPrefix(cleanedLink, destAbs) {
				return fmt.Errorf("cipherlock: refusing link %q -> %q outside destination", header.Name, header.Linkname)
			}
			if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
				return err
			}
			if err := os.Link(cleanedLink, target); err != nil {
				return err
			}
		}
	}

	return nil
}

// startsWithDotDot reports whether a cleaned relative path begins with ".."
// (i.e. tries to escape its root).
func startsWithDotDot(cleaned string) bool {
	if cleaned == ".." {
		return true
	}
	return strings.HasPrefix(cleaned, ".."+string(filepath.Separator))
}

// pathHasPrefix reports whether abs is the same as or lies under root, after
// both have been cleaned. Both arguments must be absolute (or at least
// relative-but-canonical) and use the same separator.
func pathHasPrefix(abs, root string) bool {
	abs = filepath.Clean(abs)
	root = filepath.Clean(root)
	if abs == root {
		return true
	}
	return strings.HasPrefix(abs, root+string(filepath.Separator))
}
