package iolib

import (
	"fmt"
	"io/ioutil"
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
	bytes, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("Failed to read `%s`: %w", filePath, err)
	}
	return bytes, nil
}

func ReadStdin() ([]byte, error) {
	bytes, err := ioutil.ReadAll(os.Stdin)
	if err != nil {
		return nil, fmt.Errorf("Failed to read stdin: %w", err)
	}
	return bytes, nil
}

func WriteInputFile(filePath string, bytes []byte) error {
	if filePath == "" {
		return WriteStdout(bytes)
	} else {
		return WriteFile(filePath, bytes)
	}
}

func WriteFile(filePath string, bytes []byte) error {
	err := ioutil.WriteFile(filePath, bytes, 0644)
	if err != nil {
		return fmt.Errorf("Failed to write `%s`: %w", filePath, err)
	}
	return nil
}

func WriteStdout(bytes []byte) error {
	_, err := os.Stdout.Write(bytes)
	if err != nil {
		return fmt.Errorf("Failed to write stdout: %w", err)
	}
	return nil
}
