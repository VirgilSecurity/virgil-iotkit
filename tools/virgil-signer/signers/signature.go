package signers

import (
    "bytes"
    "encoding/asn1"
    "fmt"
    "io/ioutil"
    "math/big"

    "gopkg.in/virgilsecurity/virgil-crypto-go.v5"
)

var (
    crypto = virgil_crypto_go.NewVirgilCrypto()
)

func signByFileKey(keyFilePath string, data *[]byte) ([]byte, error) {
    fmt.Printf("Signing data by %s key\n", keyFilePath)
    keyFileBytes, err := ioutil.ReadFile(keyFilePath)
    if err != nil {
        return []byte{}, err
    }
    fmt.Println("Bytes from key file are read")

    privateKey, err := crypto.ImportPrivateKey(keyFileBytes, "")
    if err != nil {
        return []byte{}, err
    }
    fmt.Println("Private key imported")

    signature, err := crypto.Sign(*data, privateKey)
    if err != nil {
        return []byte{}, err
    }
    fmt.Println("Data signed by crypto")

    signatureBytes, err := extractSignatureBytes(&signature)
    if err != nil {
        return []byte{}, err
    } else {
        fmt.Println("Signature bytes from sign are extracted")
        return signatureBytes, nil
    }

}

func extractSignatureBytes(signatureBytes *[]byte) ([]byte, error) {

    sign := &Signature{}
    if _, err := asn1.Unmarshal(*signatureBytes, sign); err != nil {
        return []byte{}, err
    }

    innerSignatures := &InnerSignature{}
    if _, err := asn1.Unmarshal(sign.Sign, innerSignatures); err != nil {
        return []byte{}, err
    }

    rBytes := innerSignatures.R.Bytes()
    sBytes := innerSignatures.S.Bytes()

    // Make sure that each part is 32 bytes length, if not - insert zeroes at the beginning
    rBytes = adjustLengthTo32(rBytes)
    sBytes = adjustLengthTo32(sBytes)

    buf := new(bytes.Buffer)
    buf.Write(rBytes)
    buf.Write(sBytes)

    return buf.Bytes(), nil
}

func adjustLengthTo32(b []byte) []byte {
    for ;len(b) < 32; {
        b = append(b, 0)
        copy(b[0+1:], b[0:])
        b[0] = byte(0)
    }
    return b
}

type HashedType struct {
    Oid 	asn1.ObjectIdentifier
    Null 	asn1.RawValue
}

type Signature struct {
    Hashed 	HashedType
    Sign   	[]byte
}

type InnerSignature struct {
    R, S 	*big.Int
}
