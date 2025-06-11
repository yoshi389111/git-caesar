package iolib

import (
	"fmt"
	"io"
	"net/http"
)

func FetchContent(uri string) ([]byte, error) {
	resp, err := http.Get(uri)
	if err != nil {
		return nil, fmt.Errorf("Failed to get http. URL=`%s`\n\t%w", uri, err)
	}
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}
