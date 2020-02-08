
#ifndef  _W5500_NETWORK_H_
#define  _W5500_NETWORK_H_

#define _WIZCHIP_  W5500

#define W5500_SS PA4
#define W5500_INT PA3
#define W5500_RST PA2
#define W5500_SPI SPI

#define W5500_UDP_PORT 4100

#include <Arduino.h>
#include <SPI.h>
#include <Ethernet/W5500/w5500.h>
#include <Ethernet/socket.h>
#include <virgil/iot/logger/logger.h>

using namespace VirgilIoTKit;

// Primitives
int wiznet_init(void);

extern uint8_t udp_sock;

#endif   // _W5500_NETWORK_H_
