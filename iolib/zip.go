package iolib

import (
	"archive/zip"
	"fmt"
	"io"
)

func AppendZieEntry(zipWriter *zip.Writer, entryName string, entryBody []byte) error {
	entryWriter, err := zipWriter.Create(entryName)
	if err != nil {
		return fmt.Errorf("failed to generate ZipWriter: %w", err)
	}
	_, err = entryWriter.Write(entryBody)
	if err != nil {
		return fmt.Errorf("failed to add entry to ZipWriter: name=`%s`: %w", entryName, err)
	}
	return nil
}

func ExtractZipEntry(zipReader *zip.Reader, fileName string) ([]byte, error) {
	var targetFile *zip.File
	for _, file := range zipReader.File {
		if file.Name == fileName {
			targetFile = file
			break
		}
	}
	if targetFile == nil {
		return nil, fmt.Errorf("`%s` not found", fileName)
	}
	fileReader, err := targetFile.Open()
	if err != nil {
		return nil, fmt.Errorf("failed to open ZIP for read: %w", err)
	}
	defer fileReader.Close()
	fileData, err := io.ReadAll(fileReader)
	if err != nil {
		return nil, fmt.Errorf("failed to read entries from ZIP: %w", err)
	}
	return fileData, nil
}
