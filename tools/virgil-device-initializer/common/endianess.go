package common

import (
	"encoding/binary"
	"unsafe"
)

var SystemEndian binary.ByteOrder

func init() {
	buf := [2]byte{}
	*(*uint16)(unsafe.Pointer(&buf[0])) = uint16(0xABCD)

	switch buf {
	case [2]byte{0xCD, 0xAB}:
		SystemEndian = binary.LittleEndian
	case [2]byte{0xAB, 0xCD}:
		SystemEndian = binary.BigEndian
	default:
		panic("Could not determine system endianness.")
	}
}
