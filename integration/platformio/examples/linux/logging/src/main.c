
#include <virgil/iot/logger/logger.h>

/******************************************************************************/
int main()
{
// Initialize Logger module
    vs_logger_init(VS_LOGLEV_DEBUG);
    VS_LOG_INFO("Test logging.");


}
