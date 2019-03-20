
#ifndef VIRGIL_DEMO_SORAA_LAMP_INITIALIZER_CRC16_H
#define VIRGIL_DEMO_SORAA_LAMP_INITIALIZER_CRC16_H

#include <cstdint>
#include <cstddef>

class Crc16 {
    Crc16() = delete;
    ~Crc16() = delete;
public:
    static uint16_t calc(const uint8_t * data, size_t dataSz);
};


#endif //VIRGIL_DEMO_SORAA_LAMP_INITIALIZER_CRC16_H
