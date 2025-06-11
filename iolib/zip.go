package iolib

import (
	"archive/zip"
	"fmt"
	"io"
)

func AppendZieEntry(zipWriter *zip.Writer, entryName string, entryBody []byte) error {
	entryWriter, err := zipWriter.Create(entryName)
	if err != nil {
		return fmt.Errorf("Failed to generate ZipWriter.\n\t%w", err)
	}
	_, err = entryWriter.Write(entryBody)
	if err != nil {
		return fmt.Errorf("Failed to add entry to ZipWriter. name=`%s`\n\t%w", entryName, err)
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
		return nil, fmt.Errorf("`%s` not found.", fileName)
	}
	fileReader, err := targetFile.Open()
	if err != nil {
		return nil, fmt.Errorf("Failed to open ZIP for read.\n\t%w", err)
	}
	defer fileReader.Close()
	fileData, err := io.ReadAll(fileReader)
	if err != nil {
		return nil, fmt.Errorf("Failed to read entries from ZIP.\n\t%w", err)
	}
	return fileData, nil
}
