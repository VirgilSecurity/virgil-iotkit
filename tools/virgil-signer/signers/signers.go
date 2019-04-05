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

func newFooterSignatureByKey(keyPath string, data *[]byte) (FooterSignature, error) {
    // example of name: auth_20559_auth_2.key
    _, file := filepath.Split(keyPath)
    s := strings.Split(file, "_")

    // get key type
    var keyType int
    switch s[0] {
    case "auth":
        keyType = 4
    case "firmware":
        keyType = 1
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
    updateFilePath := fwPathNoExtension + "_Update.bin"
    progFilePath := fwPathNoExtension + "_Prog.bin"

    fmt.Println("\nStart creation of _Update file")
    if err := s.createFile(updateFilePath, false); err != nil {
        return err
    }

    fmt.Println("\nStart creation of _Prog file")
    if err := s.createFile(progFilePath, true); err != nil {
        return err
    }

    return nil
}

func (s *Signer) createFile(filePath string, withFiller bool) error {
    // Get firmware bytes
    firmwareBytesWithoutSign, err := ioutil.ReadFile(s.FirmwarePath)
    if err != nil {
        return err
    }
    firmwareLength := len(firmwareBytesWithoutSign)

    // Compute filler length
    var fillerLength = 0
    if withFiller {
        fillerLength = s.ProgFileSize - (HEADER_SIZE + firmwareLength + FOOTER_SIZE)
    }

    // Prepare Header
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

    header := Header{
        CodeOffset:       HEADER_SIZE,
        CodeLength:       uint32(firmwareLength),
        FooterOffset:     uint32(HEADER_SIZE + firmwareLength + fillerLength),
        FooterLength:     FOOTER_SIZE,
        FwVersion:        fwVersion,
        Padding:          0x00,
        ChunkSize:        uint16(s.ChunkSize),
        FirmwareLength:   uint32(len(firmwareBytesWithoutSign)),
        AppSize:          uint32(s.ProgFileSize),
    }
    copy(header.ManufacturerID[:], s.Manufacturer)
    copy(header.DeviceID[:], s.Model)

    fmt.Printf("Header prepared: %+v \n", &header)


    // Write header and FW code with 0xFF section to buffer:
    buf := new(bytes.Buffer)

    // write header
    if err := binary.Write(buf, binary.BigEndian, header); err != nil {
        return err
    }
    fmt.Println("Header is written to buffer")

    buf.Write(firmwareBytesWithoutSign)
    fmt.Println("Firmware code is written to buffer")

    if withFiller {
        fmt.Printf("Writing 0xFF section: %d bytes to %d-bytes buffer\n", fillerLength, len(buf.Bytes()))
        for i := 0; i < fillerLength; i++ {
            buf.WriteByte(0xFF)
        }
    }

    // Sign data and prepare footer
    dataToSign := buf.Bytes()
    var authSign, firmwareSign FooterSignature
    if authSign, err = newFooterSignatureByKey(s.AuthKeyPath, &dataToSign); err != nil {
        return err
    }
    if firmwareSign, err = newFooterSignatureByKey(s.FirmwareKeyPath, &dataToSign); err != nil {
        return err
    }
    footer := Footer{
        AuthSign:       authSign,
        FirmwareSign:   firmwareSign,

    }
    fmt.Printf("Footer prepared: %+v \n", &footer)

    // Write footer to buffer
    if err := binary.Write(buf, binary.BigEndian, footer); err != nil {
        return err
    }
    fmt.Println("Footer is written to buffer")

    // Write buffer to file
    if err := ioutil.WriteFile(filePath, buf.Bytes(), os.ModePerm); err != nil {
        return err
    }
    fmt.Println("File saved to: ", filePath)

    return nil
}
