
#include <Arduino.h>
#include <virgil/iot/logger/logger.h>
#include <hardware/w5500/w5500_network.hpp>

using namespace VirgilIoTKit;

void W5500_int(void);

/******************************************************************************/
void setup()
{
  pinMode(W5500_INT, INPUT_PULLUP);
  attachInterrupt(W5500_INT, W5500_int, LOW);
  // Initialize serial port for logging (see: impl/logger/logger-impl.c )
  Serial1.begin(115200);

  // Initialize Logger module
  vs_logger_init(VS_LOGLEV_DEBUG);

  // Withnet initialization
  wiznet_init();

  VS_LOG_INFO("Starting test logging");
}
/******************************************************************************/
void loop()
{
  char *snd_b = "1111";
  uint8_t dbuf[255];
  uint8_t size;
  uint8_t dst_addr[4] = {255,255,255,255 };
  delay(1000);
  VS_LOG_INFO("Loop print logging IR=%d", getSn_IR(udp_sock));
  //sendto(udp_sock,(uint8_t *) snd_b,sizeof(snd_b),dst_addr,4100 );
}

// *********************************************************************************
void W5500_int(void) {
  uint8_t dsize;
  uint8_t dbuf[getSn_RxMAX(udp_sock)];

  VS_LOG_INFO("W5500 Int IR=%d", getSn_IR(udp_sock));
  setSn_IR(udp_sock, Sn_IR_RECV);
  
  if((dsize = getSn_RX_RSR(udp_sock)) > 0){     	
    VS_LOG_INFO("INT: Found data size: %d ",dsize);
    int ret = recv(udp_sock, (uint8_t *) &dbuf, dsize);
    dbuf[ret] = 0;
    VS_LOG_INFO("INT: Data received Count: %d DATA: %s ",ret, &dbuf);
  }
  
  //wizchip_clrinterrupt(IK_SOCK_ALL);
}

