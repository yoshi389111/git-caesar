package iolib

import (
	"archive/zip"
	"fmt"
	"io/ioutil"
)

func AppendZieEntry(zipWriter *zip.Writer, entryName string, entryBody []byte) error {
	entryWriter, err := zipWriter.Create(entryName)
	if err != nil {
		return err
	}
	_, err = entryWriter.Write(entryBody)
	if err != nil {
		return err
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
		return nil, err
	}
	defer fileReader.Close()
	fileData, err := ioutil.ReadAll(fileReader)
	if err != nil {
		return nil, err
	}
	return fileData, nil
}
