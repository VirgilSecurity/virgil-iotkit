
#ifndef VIRGIL_IOT_LAMP_INITIALIZER_CRC16_H
#define VIRGIL_IOT_LAMP_INITIALIZER_CRC16_H

#include <cstdint>
#include <cstddef>

class Crc16 {
    Crc16() = delete;
    ~Crc16() = delete;
public:
    static uint16_t calc(const uint8_t * data, size_t dataSz);
};


#endif //VIRGIL_IOT_LAMP_INITIALIZER_CRC16_H
