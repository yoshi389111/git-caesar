package iolib

import (
	"fmt"
	"io"
	"os"
)

func ExistsFile(filePath string) bool {
	_, err := os.Stat(filePath)
	return err == nil
}

func ReadInputFile(filePath string) ([]byte, error) {
	if filePath == "" {
		return ReadStdin()
	} else {
		return ReadFile(filePath)
	}
}

func ReadFile(filePath string) ([]byte, error) {
	rawContent, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read `%s`: %w", filePath, err)
	}
	return rawContent, nil
}

func ReadStdin() ([]byte, error) {
	rawContent, err := io.ReadAll(os.Stdin)
	if err != nil {
		return nil, fmt.Errorf("failed to read stdin: %w", err)
	}
	return rawContent, nil
}

func WriteOutputFile(filePath string, rawContent []byte) error {
	if filePath == "" {
		return WriteStdout(rawContent)
	} else {
		return WriteFile(filePath, rawContent)
	}
}

func WriteFile(filePath string, rawContent []byte) error {
	err := os.WriteFile(filePath, rawContent, 0644)
	if err != nil {
		return fmt.Errorf("failed to write `%s`: %w", filePath, err)
	}
	return nil
}

func WriteStdout(rawContent []byte) error {
	_, err := os.Stdout.Write(rawContent)
	if err != nil {
		return fmt.Errorf("failed to write stdout: %w", err)
	}
	return nil
}
