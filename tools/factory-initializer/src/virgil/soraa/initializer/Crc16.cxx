
#include <virgil/soraa/initializer/Crc16.h>

uint16_t Crc16::calc(const uint8_t * data, size_t dataSz) {
    uint16_t crc = 0;
    const uint8_t * p = data;

    while (dataSz--) {
        crc ^= *p++ << 8;

        for (int i = 0; i < 8; i++)
            crc = crc & 0x8000 ? (crc << 1) ^ 0x1021 : crc << 1;
    }

    return crc;
}