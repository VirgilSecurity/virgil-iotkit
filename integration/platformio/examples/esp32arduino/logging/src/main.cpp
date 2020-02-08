
#include <Arduino.h>
#include <virgil/iot/logger/logger.h>

using namespace VirgilIoTKit;

/******************************************************************************/
void setup()
{
// Initialize serial port for logging (see: impl/logger/logger-impl.c )   
   Serial.begin(115200);
// Initialize Logger module
    vs_logger_init(VS_LOGLEV_DEBUG);

    VS_LOG_INFO("Starting test logging");

}
/******************************************************************************/
void loop()
{
  delay(1000);
  VS_LOG_INFO("Loop print logging");

}

