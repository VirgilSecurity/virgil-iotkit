//   Copyright (C) 2015-2019 Virgil Security Inc.
//
//   All rights reserved.
//
//   Redistribution and use in source and binary forms, with or without
//   modification, are permitted provided that the following conditions are
//   met:
//
//       (1) Redistributions of source code must retain the above copyright
//       notice, this list of conditions and the following disclaimer.
//
//       (2) Redistributions in binary form must reproduce the above copyright
//       notice, this list of conditions and the following disclaimer in
//       the documentation and/or other materials provided with the
//       distribution.
//
//       (3) Neither the name of the copyright holder nor the names of its
//       contributors may be used to endorse or promote products derived from
//       this software without specific prior written permission.
//
//   THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
//   IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
//   WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
//   DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
//   INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
//   (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
//   SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
//   HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
//   STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
//   IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
//   POSSIBILITY OF SUCH DAMAGE.
//
//   Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>

package utility

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"../converters"
	"../firmware"
	"../signers"
)

const (
	TIME_OFFSET = 1420070400 // 01/01/2015 @ 12:00am (UTC)
)

type SignerUtility struct {
	Signer          signers.SignerInterface
	FirmwarePath    string
	ProgFileSize    int
	FirmwareVersion string
	Manufacturer    string
	Model           string
	ChunkSize       int

	progFile *firmware.ProgFile
}

func (s *SignerUtility) CreateSignedFirmware() (err error) {
	fwPath := s.FirmwarePath
	fwPathNoExtension := strings.TrimSuffix(fwPath, filepath.Ext(fwPath))
	progFilePath := fwPathNoExtension + "_Prog.bin"
	updateFilePath := fwPathNoExtension + "_Update.bin"

	// Create _Prog file
	if err = s.createProgFile(progFilePath); err != nil {
		return fmt.Errorf("failed to create _Prog file: %v", err)
	}

	// Create _Update file
	if err = s.createUpdateFile(updateFilePath); err != nil {
		return fmt.Errorf("failed to create _Update file: %v", err)
	}

	return nil
}

func (s *SignerUtility) createProgFile(filePath string) error {
	progBuf := new(bytes.Buffer)

	// FW code
	fmt.Println("\nStart creation of _Prog file")
	firmwareBytesWithoutSign, err := ioutil.ReadFile(s.FirmwarePath)
	if err != nil {
		return err
	}

	// Write to firmware code to buf
	if err := binary.Write(progBuf, binary.BigEndian, firmwareBytesWithoutSign); err != nil {
		return err
	}

	// Calculate filler length
	fillerLength := s.calculateFillerSize(firmwareBytesWithoutSign)
	fmt.Printf("0xFF (filler) section length: %d bytes\n", fillerLength)

	// Filler
	var filler []byte
	for i := 0; i < fillerLength; i++ {
		filler = append(filler, 0xFF)
	}

	// Write filler to buffer
	if err := binary.Write(progBuf, binary.BigEndian, filler); err != nil {
		return err
	}

	// Footer
	footer := new(firmware.Footer)
	// - signatures count
	signaturesCount := uint8(len(s.Signer.SignerKeyEcTypes()))
	footer.SignaturesCount = signaturesCount
	// - descriptor
	version, err := s.prepareVersion()
	if err != nil {
		return err
	}

	descriptor := new(firmware.Descriptor)
	copy(descriptor.ManufactureID[:], s.Manufacturer)
	copy(descriptor.DeviceType[:], s.Model)
	descriptor.Version = version
	descriptor.Padding = 0x00
	descriptor.ChunkSize = uint16(s.ChunkSize)
	descriptor.FirmwareLength = uint32(len(firmwareBytesWithoutSign))
	descriptor.AppSize = uint32(s.ProgFileSize)

	footer.Descriptor = *descriptor
	fmt.Printf("Descriptor prepared: %+v\n", footer.Descriptor)

	// Write Footer meta to buffer
	if err := binary.Write(progBuf, binary.BigEndian, signaturesCount); err != nil {
		return err
	}
	if err := binary.Write(progBuf, binary.BigEndian, footer.Descriptor); err != nil {
		return err
	}

	// Prepare signatures
	signatures, err := s.Signer.Sign(progBuf.Bytes())
	if err != nil {
		return err
	}
	footer.Signatures = signatures

	// Write signatures to buffer
	for _, signature := range footer.Signatures {
		signatureBytes, err := signature.ToBytes()
		if err != nil {
			return err
		}
		if err := binary.Write(progBuf, binary.BigEndian, signatureBytes); err != nil {
			return err
		}
	}

	// Save to file
	if err := saveBufferToFile(progBuf, filePath); err != nil {
		return err
	}

	// Save struct for further usage
	progFile := new(firmware.ProgFile)
	progFile.FirmwareCode = firmwareBytesWithoutSign
	progFile.Filler = filler
	progFile.Footer = *footer
	s.progFile = progFile

	return nil
}

func (s *SignerUtility) createUpdateFile(filePath string) error {
	fmt.Println("\nStart creation of _Update file")
	updateBuf := new(bytes.Buffer)

	// Header
	fwLength := len(s.progFile.FirmwareCode)
	footerLen := s.calculateFooterSize()
	header := firmware.Header{
		CodeOffset:      firmware.HEADER_SIZE,
		CodeLength:      uint32(fwLength),
		FooterOffset:    uint32(firmware.HEADER_SIZE + fwLength),
		FooterLength:    uint32(footerLen),
		SignaturesCount: s.progFile.Footer.SignaturesCount,
		Descriptor:      s.progFile.Footer.Descriptor,
	}
	fmt.Printf("Header prepared: %+v\n", header)

	// Write header to buffer
	if err := binary.Write(updateBuf, binary.BigEndian, header); err != nil {
		return err
	}

	// Write FW code to buffer
	if err := binary.Write(updateBuf, binary.BigEndian, s.progFile.FirmwareCode); err != nil {
		return err
	}

	// Write Footer meta to buffer
	if err := binary.Write(updateBuf, binary.BigEndian, s.progFile.Footer.SignaturesCount); err != nil {
		return err
	}
	if err := binary.Write(updateBuf, binary.BigEndian, s.progFile.Footer.Descriptor); err != nil {
		return err
	}

	// Write signatures to buffer
	for _, signature := range s.progFile.Footer.Signatures {
		signatureBytes, err := signature.ToBytes()
		if err != nil {
			return err
		}
		if err := binary.Write(updateBuf, binary.BigEndian, signatureBytes); err != nil {
			return err
		}
	}

	// Save to file
	if err := saveBufferToFile(updateBuf, filePath); err != nil {
		return err
	}

	return nil
}

func (s *SignerUtility) prepareVersion() (ver firmware.Version, err error) {
	// Version parts
	versionParts := strings.Split(s.FirmwareVersion, ".")
	if len(versionParts) != 4 {
		return ver, fmt.Errorf("version parts amount is not 4: %s", versionParts)
	}

	major, err := stringToUint8(versionParts[0])
	if err != nil {
		return ver, err
	}
	minor, err := stringToUint8(versionParts[1])
	if err != nil {
		return ver, err
	}
	patch, err := stringToUint8(versionParts[2])
	if err != nil {
		return ver, err
	}
	build, err := stringToUint32(versionParts[3])
	if err != nil {
		return ver, err
	}
	// Timestamp
	currentTime := time.Now().UTC().Unix()
	timestamp := uint32(currentTime - TIME_OFFSET)

	ver = firmware.Version{
		Major:     major,
		Minor:     minor,
		Patch:     patch,
		Build:     build,
		Timestamp: timestamp,
	}

	return ver, nil
}

func (s *SignerUtility) calculateFooterSize() int {
	footerSize := firmware.FOOTER_META_SIZE
	for _, ecType := range s.Signer.SignerKeyEcTypes() {
		footerSize += firmware.SIGNATURE_META_SIZE                // meta in signature block
		footerSize += converters.GetSignatureSizeByECType(ecType) // signature
		footerSize += converters.GetPublicKeySizeByECType(ecType) // public key
	}
	return footerSize
}

func (s *SignerUtility) calculateFillerSize(fwCode []byte) int {
	fillerLength := s.ProgFileSize - (len(fwCode) + s.calculateFooterSize())
	return fillerLength
}

func saveBufferToFile(buf *bytes.Buffer, filePath string) error {
	if err := ioutil.WriteFile(filePath, buf.Bytes(), os.ModePerm); err != nil {
		return err
	}
	fmt.Println("File saved: ", filePath)
	return nil
}

func stringToUint8(s string) (uint8, error) {
	intValue, err := strconv.ParseUint(s, 10, 8)
	if err != nil {
		return 0, fmt.Errorf("can`t convert %s string to uint8: %s", s, err)
	}
	return uint8(intValue), nil
}

func stringToUint32(s string) (uint32, error) {
	intValue, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("can`t convert %s string to uint32: %s", s, err)
	}
	return uint32(intValue), nil
}
