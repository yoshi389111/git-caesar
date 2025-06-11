package iolib

import (
	"fmt"
	"io"
	"net/http"
)

func FetchContent(uri string) ([]byte, error) {
	resp, err := http.Get(uri)
	if err != nil {
		return nil, fmt.Errorf("failed to get http: URL=`%s`: %w", uri, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("http request failed: URL=`%s` status=%d", uri, resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}
