//go:build !unix

package cert

import "os"

func lockDir(dir string) (func(), error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	return func() {}, nil
}
