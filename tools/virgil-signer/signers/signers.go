package signers

import (
    "bytes"
    "encoding/binary"
    "fmt"
    "io/ioutil"
    "os"
    "path/filepath"
    "strconv"
    "strings"
)

const (
    HEADER_SIZE = 56
    FOOTER_SIZE = (1 + 2 + 64) * 2  // (key type + key id + signature) * keys count
)

type Signer struct {
    FirmwarePath    string
    FirmwareKeyPath string
    AuthKeyPath     string
    ProgFileSize    int
    FirmwareVersion string
    Manufacturer    string
    Model           string
    ChunkSize       int
    ApplicationType string
    BuildTime       string
}

type ProgFile struct {
    fwCode          []byte
    fillerLength    int
    footer          Footer
}

type Header struct {
    CodeOffset         uint32
    CodeLength         uint32
    FooterOffset       uint32
    FooterLength       uint32
    ManufacturerID     [4]byte
    DeviceID           [4]byte
    FwVersion          FirmwareVersion
    Padding            byte
    ChunkSize          uint16
    FirmwareLength     uint32
    AppSize            uint32
}

type FirmwareVersion struct {
    ApplicationType [4]byte
    Major           uint8
    Minor           uint8
    Patch           uint8
    DevMilestone    uint8
    DevBuild        uint8
    BuildTimestamp  [12]byte
}

type Footer struct {
    FirmwareSign     FooterSignature
    AuthSign         FooterSignature
}

type FooterSignature struct {
    KeyType          uint8
    SignerID         uint16
    Signature        [64]byte
}

func newFooterSignatureByKey(keyPath string, data []byte) (FooterSignature, error) {
    // example of name: auth_20559_auth_2.key
    _, file := filepath.Split(keyPath)
    s := strings.Split(file, "_")

    // get key type
    keyTypeStr := s[0]
    var keyType int

    switch keyTypeStr {
    case "auth":
        keyType = 4
    case "firmware":
        keyType = 1
    default:
        return FooterSignature{}, fmt.Errorf("unknown key type: %s (%s)", keyTypeStr, file)
    }

    // get key id
    keyID := s[1]
    keyIDInt, _ := strconv.ParseUint(keyID, 10, 16)
    // get signature
    signatureBytes, err := signByFileKey(keyPath, data)
    if err != nil {
        return FooterSignature{}, err
    }
    var signatureArr [64]byte
    copy(signatureArr[:], signatureBytes)

    return FooterSignature{
        KeyType: uint8(keyType),
        SignerID: uint16(keyIDInt),
        Signature: signatureArr,
    }, nil
}

func (s *Signer) CreateSignedFirmware() error {
    fwPath := s.FirmwarePath
    fwPathNoExtension := strings.TrimSuffix(fwPath, filepath.Ext(fwPath))
    progFilePath := fwPathNoExtension + "_Prog.bin"
    updateFilePath := fwPathNoExtension + "_Update.bin"

    var progFile *ProgFile
    var err error
    // Create _Prog file
    if progFile, err = s.createProgFile(progFilePath); err !=nil {
        return err
    }

    // Create _Update file
    if err = s.createUpdateFile(progFile, updateFilePath); err != nil {
        return err
    }
    return nil
}

func (s *Signer) createProgFile(filePath string) (*ProgFile, error) {
    fmt.Println("\nStart creation of _Prog file")
    firmwareBytesWithoutSign, err := ioutil.ReadFile(s.FirmwarePath)
    if err != nil {
        return &ProgFile{}, err
    }

    progFile := new(ProgFile)
    progFile.fwCode = firmwareBytesWithoutSign
    progFile.fillerLength = s.ProgFileSize - (len(progFile.fwCode) + FOOTER_SIZE)

    progBuf := new(bytes.Buffer)

    progBuf.Write(progFile.fwCode)
    fmt.Println("Firmware code is written to buffer")

    // Write 0xFF section
    progFile.writeFiller(progBuf)

    // Create and write footer, buffer contains firmware code + 0xFF section
    if err := progFile.newFooter(progBuf.Bytes(), s); err != nil {
        return &ProgFile{}, err
    }
    if err := binary.Write(progBuf, binary.BigEndian, progFile.footer); err != nil {
        return &ProgFile{}, err
    }
    fmt.Println("Footer is written to buffer")

    // Save buffer to file
    if err := saveBufferToFile(progBuf, filePath); err != nil {
        return &ProgFile{}, err
    }

    return progFile, nil
}

// create _Update file based on existing _Prog file
func (s *Signer) createUpdateFile(progFile *ProgFile, filePath string) error {
    fmt.Println("\nStart creation of _Update file")
    updateBuf := new(bytes.Buffer)

    // Write header
    if err := s.writeHeader(updateBuf, progFile); err != nil {
        return err
    }
    fmt.Println("Header is written to buffer")

    // Write Firmware code
    updateBuf.Write(progFile.fwCode)
    fmt.Println("Firmware code is written to buffer")

    // Write footer from _Prog file
    fmt.Printf("Footer from _Prog file: %+v \n", progFile.footer)
    if err := binary.Write(updateBuf, binary.BigEndian, progFile.footer); err != nil {
        return err
    }
    fmt.Println("Footer from _Prog file is written to buffer")

    // Save buffer to file
    if err := saveBufferToFile(updateBuf, filePath); err != nil {
        return err
    }
    return nil
}

func saveBufferToFile(buf *bytes.Buffer, filePath string) error {
    if err := ioutil.WriteFile(filePath, buf.Bytes(), os.ModePerm); err != nil {
        return err
    }
    fmt.Println("File saved: ", filePath)
    return nil
}

func (s *Signer) writeHeader(buf *bytes.Buffer, p *ProgFile) error {
    var versionParts [5]uint8
    for i, val := range strings.Split(s.FirmwareVersion, ".") {
        intValue, _ := strconv.ParseUint(val, 10, 8)
        versionParts[i] = uint8(intValue)
    }
    fwVersion := FirmwareVersion{
        Major:            versionParts[0],
        Minor:            versionParts[1],
        Patch:            versionParts[2],
        DevMilestone:     versionParts[3],
        DevBuild:         versionParts[4],
    }
    copy(fwVersion.ApplicationType[:], s.ApplicationType)
    copy(fwVersion.BuildTimestamp[:], s.BuildTime)

    fwLength := len(p.fwCode)

    header := Header{
        CodeOffset:       HEADER_SIZE,
        CodeLength:       uint32(fwLength),
        FooterOffset:     uint32(HEADER_SIZE + fwLength + p.fillerLength),
        FooterLength:     FOOTER_SIZE,
        FwVersion:        fwVersion,
        Padding:          0x00,
        ChunkSize:        uint16(s.ChunkSize),
        FirmwareLength:   uint32(fwLength),
        AppSize:          uint32(s.ProgFileSize),
    }
    copy(header.ManufacturerID[:], s.Manufacturer)
    copy(header.DeviceID[:], s.Model)

    fmt.Printf("Header prepared: %+v \n", header)

    if err := binary.Write(buf, binary.BigEndian, header); err != nil {
       return err
    }
    return nil
}

func (p *ProgFile) writeFiller(buf *bytes.Buffer) {
   fmt.Printf("Writing 0xFF section: %d bytes to %d-bytes buffer\n", p.fillerLength, len(buf.Bytes()))
   for i := 0; i < p.fillerLength; i++ {
       buf.WriteByte(0xFF)
   }
}

func (p *ProgFile) newFooter(dataToSign []byte, s *Signer) error {
    var authSign, firmwareSign FooterSignature
    var err error
    if authSign, err = newFooterSignatureByKey(s.AuthKeyPath, dataToSign); err != nil {
        return err
    }
    if firmwareSign, err = newFooterSignatureByKey(s.FirmwareKeyPath, dataToSign); err != nil {
        return err
    }
    footer := Footer{
        AuthSign:       authSign,
        FirmwareSign:   firmwareSign,
    }
    p.footer = footer
    fmt.Printf("Footer prepared: %+v \n", p.footer)
    return nil
}
