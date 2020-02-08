#include <stdio.h>
#include <string.h>
#include "xhw_types.h"
#include "xhw_memmap.h"
#include "xhw_spi.h"
#include "xsysctl.h"
#include "xgpio.h"
#include "xuart.h"
#include "xspi.h"
#include "xcore.h"	// for SysTick

#include "Ethernet/socket.h"
#include "Internet/DHCP/dhcp.h"

volatile uint32_t msTicks; /* counts 1ms timeTicks */
uint32_t prevTick;

///////////////////////////////////////
// Debugging Message Printout enable //
///////////////////////////////////////
#define _MAIN_DEBUG_

///////////////////////////////////
// STM32F103X SPI PIN Definition //
///////////////////////////////////
#define WIZCHIP_SPI_PERIPH    xSYSCTL_PERIPH_SPI1
#define WIZCHIP_SPI_BASE      xSPI1_BASE
#define WIZCHIP_SPI_CLK       SPI1CLK(3)
#define WIZCHIP_SPI_MOSI      SPI1MOSI(3)
#define WIZCHIP_SPI_MISO      SPI1MISO(1)
#define WIZCHIP_SPI_CLK_PIN   PA5
#define WIZCHIP_SPI_MOSI_PIN  PA7
#define WIZCHIP_SPI_MISO_PIN  PA6

/***************************************
 * SOCKET NUMBER DEFINION for Examples *
 ***************************************/
#define SOCK_DHCP			0
#define MY_MAX_DHCP_RETRY	3

/**********************************************
 * Shared Buffer Definition for LOOPBACK TEST *
 **********************************************/
#define DATA_BUF_SIZE   2048
uint8_t gDATABUF[DATA_BUF_SIZE];

/**************************************************************************//**
 * @brief Default Network Inforamtion
 *****************************************************************************/
wiz_NetInfo gWIZNETINFO = { .mac = {0x00, 0x08, 0xdc,0x00, 0xab, 0xcd},
                            .ip = {192, 168, 1, 123},
                            .sn = {255,255,255,0},
                            .gw = {192, 168, 1, 1},
                            .dns = {0,0,0,0},
                            .dhcp = NETINFO_DHCP };

//////////////////////////////////////////////////////////////////////////////////////////////
// Call back function for W5500 SPI - Theses used to parameter or reg_wizchip_xxx_cbfunc()  //
//////////////////////////////////////////////////////////////////////////////////////////////
void  wizchip_select(void);
void  wizchip_deselect(void);
void  wizchip_write(uint8_t wb);
uint8_t wizchip_read();

//////////////////////////////////////////////////////////
// Initialization and Application functions for W5500	//
//////////////////////////////////////////////////////////
void platform_init(void);
void network_init(void);

/*****************************************************************************
 * @brief SysTickIntHandler
 * Interrupt Service Routine for system tick counter
 *****************************************************************************/
void SysTickIntHandler(void)
{
	msTicks++; /* increment counter necessary in Delay()*/

	////////////////////////////////////////////////////////
	// SHOULD BE Added DHCP Timer Handler your 1s tick timer
	if(msTicks % 1000 == 0)	DHCP_time_handler();
	////////////////////////////////////////////////////////
}

/*****************************************************************************
 * @brief platform_init
 * Platform (STM32F103X) initialization for peripherals as GPIO, SPI, UARTs
 *****************************************************************************/
void platform_init(void)
{
    xSysCtlClockSet(72000000,  xSYSCTL_OSC_MAIN | xSYSCTL_XTAL_8MHZ);

    xSysCtlDelay((xSysCtlClockGet()/1000)*50); // wait 50ms

    /****************/
	/* Init Systick */
	/****************/
    xSysTickPeriodSet(xSysCtlClockGet()/1000);

	xSysTickEnable();
	xSysTickIntEnable();

    /**************************/
    /* GPIO_A For SPI CS PIN  */// It must be first to enable GPIO peripheral than other peripheral. (Otherwise, UART do not run in STM32F103X)
    /**************************/
    xSysCtlPeripheralEnable( xSYSCTL_PERIPH_GPIOA );
    xGPIODirModeSet(xGPIO_PORTA_BASE, xGPIO_PIN_4, xGPIO_DIR_MODE_OUT);

    /***********************/
    /* GPIO_A For LEDs PIN *///PA0, PA1
    /***********************/
    xGPIODirModeSet(xGPIO_PORTA_BASE, xGPIO_PIN_0 | xGPIO_PIN_1, xGPIO_DIR_MODE_OUT);


    /************/
    /* For UART */
    /************/
    xSysCtlPeripheralReset(xSYSCTL_PERIPH_UART1);
    xSysCtlPeripheralEnable(xSYSCTL_PERIPH_UART1);
    xSPinTypeUART(UART1TX,PA9);
    xSPinTypeUART(UART1RX,PA10);
    xUARTConfigSet(xUART1_BASE, 115200, (UART_CONFIG_WLEN_8 | UART_CONFIG_STOP_ONE | UART_CONFIG_PAR_NONE));
    xUARTEnable(xUART1_BASE, (UART_BLOCK_UART | UART_BLOCK_TX | UART_BLOCK_RX));


    /***********/
    /* For SPI */
    /***********/
    xSysCtlPeripheralReset(WIZCHIP_SPI_PERIPH);
    xSysCtlPeripheralEnable(WIZCHIP_SPI_PERIPH);
    xSPinTypeSPI(WIZCHIP_SPI_CLK, WIZCHIP_SPI_CLK_PIN);  // xGPIODirModeSet(xGPIO_PORTA, xGPIO_PIN_5, GPIO_TYPE_AFOUT_STD, GPIO_OUT_SPEED_50M);
    xSPinTypeSPI(WIZCHIP_SPI_MOSI,WIZCHIP_SPI_MOSI_PIN);  // xGPIODirModeSet(xGPIO_PORTA, xGPIO_PIN_7, GPIO_TYPE_AFOUT_STD, GPIO_OUT_SPEED_50M);
    xSPinTypeSPI(WIZCHIP_SPI_MISO,WIZCHIP_SPI_MISO_PIN);  // xGPIODirModeSet(xGPIO_PORTA, xGPIO_PIN_6, GPIO_TYPE_IN_FLOATING, GPIO_IN_SPEED_FIXED);
    xSPIConfigSet(WIZCHIP_SPI_BASE, xSysCtlClockGet()/2, xSPI_MOTO_FORMAT_MODE_0 | xSPI_MODE_MASTER | xSPI_MSB_FIRST | xSPI_DATA_WIDTH8);

    xSPISSSet(WIZCHIP_SPI_BASE, SPI_SS_SOFTWARE, xSPI_SS_NONE);
    xSPIEnable(WIZCHIP_SPI_BASE);

    printf("HCLK = %dMHz\r\n", (unsigned int)(xSysCtlClockGet()/1000000));
}

/******************************************************************************
 * @brief  Network Init
 * Intialize the network information to be used in WIZCHIP
 *****************************************************************************/
void network_init(void)
{
	uint8_t tmpstr[6] = {0,};
	wiz_NetInfo netinfo;

	// Set Network information from netinfo structure
	ctlnetwork(CN_SET_NETINFO, (void*)&gWIZNETINFO);

#ifdef _MAIN_DEBUG_
	// Get Network information
	ctlnetwork(CN_GET_NETINFO, (void*)&netinfo);

	// Display Network Information
	ctlwizchip(CW_GET_ID,(void*)tmpstr);

	if(netinfo.dhcp == NETINFO_DHCP) printf("\r\n=== %s NET CONF : DHCP ===\r\n",(char*)tmpstr);
	else printf("\r\n=== %s NET CONF : Static ===\r\n",(char*)tmpstr);

	printf("MAC: %02X:%02X:%02X:%02X:%02X:%02X\r\n",netinfo.mac[0],netinfo.mac[1],netinfo.mac[2],
			netinfo.mac[3],netinfo.mac[4],netinfo.mac[5]);
	printf("SIP: %d.%d.%d.%d\r\n", netinfo.ip[0],netinfo.ip[1],netinfo.ip[2],netinfo.ip[3]);
	printf("GAR: %d.%d.%d.%d\r\n", netinfo.gw[0],netinfo.gw[1],netinfo.gw[2],netinfo.gw[3]);
	printf("SUB: %d.%d.%d.%d\r\n", netinfo.sn[0],netinfo.sn[1],netinfo.sn[2],netinfo.sn[3]);
	printf("DNS: %d.%d.%d.%d\r\n", netinfo.dns[0],netinfo.dns[1],netinfo.dns[2],netinfo.dns[3]);
	printf("===========================\r\n");
#endif
}

/*******************************************************
 * @ brief Call back for ip assing & ip update from DHCP
 *******************************************************/
void my_ip_assign(void)
{
   getIPfromDHCP(gWIZNETINFO.ip);
   getGWfromDHCP(gWIZNETINFO.gw);
   getSNfromDHCP(gWIZNETINFO.sn);
   getDNSfromDHCP(gWIZNETINFO.dns);
   gWIZNETINFO.dhcp = NETINFO_DHCP;
   /* Network initialization */
   network_init();      // apply from dhcp
#ifdef _MAIN_DEBUG_
   printf("DHCP LEASED TIME : %ld Sec.\r\n", getDHCPLeasetime());
#endif
}

/************************************
 * @ brief Call back for ip Conflict
 ************************************/
void my_ip_conflict(void)
{
#ifdef _MAIN_DEBUG_
	printf("CONFLICT IP from DHCP\r\n");
#endif
   //halt or reset or any...
   while(1); // this example is halt.
}

/******************************************************************************
 * @brief  Main function
 * Main is called from _program_start, see assembly startup file
 *****************************************************************************/
int main(void)
{
   uint8_t tmp;
   uint8_t memsize[2][8] = { {2,2,2,2,2,2,2,2},{2,2,2,2,2,2,2,2}};
   uint8_t my_dhcp_retry = 0;
   uint32_t led_msTick = 1000;

   platform_init();

   /////////////////////////////////////////////
   // Register SPI callback function of W5500 //
   /////////////////////////////////////////////

   /* Critical section callback - No use in this example */
   //reg_wizchip_cris_cbfunc(0, 0);

   /* Chip selection call back */
#if   _WIZCHIP_IO_MODE_ == _WIZCHIP_IO_MODE_SPI_VDM_
    reg_wizchip_cs_cbfunc(wizchip_select, wizchip_deselect);
#elif _WIZCHIP_IO_MODE_ == _WIZCHIP_IO_MODE_SPI_FDM_
    reg_wizchip_cs_cbfunc(wizchip_select, wizchip_select);  // CS must be tried with LOW.
#else
   #if (_WIZCHIP_IO_MODE_ & _WIZCHIP_IO_MODE_SIP_) != _WIZCHIP_IO_MODE_SIP_
      #error "Unknown _WIZCHIP_IO_MODE_"
   #else
      reg_wizchip_cs_cbfunc(wizchip_select, wizchip_deselect);
   #endif
#endif
    /* SPI Read & Write callback function */
    reg_wizchip_spi_cbfunc(wizchip_read, wizchip_write);
    /////////////////////////////////////////////


    /* wizchip initialize*/
    if(ctlwizchip(CW_INIT_WIZCHIP,(void*)memsize) == -1)
    {
       printf("WIZCHIP Initialized fail.\r\n");
       while(1);
    }

    /* PHY link status check */
    do
    {
       if(ctlwizchip(CW_GET_PHYLINK, (void*)&tmp) == -1)
          printf("Unknown PHY Link stauts.\r\n");
    }while(tmp == PHY_LINK_OFF);


    /* Network initialization */
    //network_init(); // Static netinfo setting

    /************************************************/
    /* WIZnet W5500 Code Examples : 				*/
    /* Implemented using ioLibrary_BSD Socket APIs	*/
    /************************************************/
    /* >> DHCP Client 								*/
    /************************************************/

    // must be set the default mac before DHCP started.
	setSHAR(gWIZNETINFO.mac);

	DHCP_init(SOCK_DHCP, gDATABUF);
	// if you want defiffent action instead defalut ip assign,update, conflict,
	// if cbfunc == 0, act as default.
	reg_dhcp_cbfunc(my_ip_assign, my_ip_assign, my_ip_conflict);

    prevTick = msTicks;

    /* Main Loop */
    while(1)
    {
		switch(DHCP_run())
		{
			case DHCP_IP_ASSIGN:
			case DHCP_IP_CHANGED:
				/* If this block empty, act with default_ip_assign & default_ip_update */
				//
				// This example calls my_ip_assign in the two case.
				//
				// Add to ...
				//
				break;
			case DHCP_IP_LEASED:
				//
				// TO DO YOUR NETWORK APPs.
				//
				break;
			case DHCP_FAILED:
				/* ===== Example pseudo code =====  */
				// The below code can be replaced your code or omitted.
				// if omitted, retry to process DHCP
				my_dhcp_retry++;
				if(my_dhcp_retry > MY_MAX_DHCP_RETRY)
				{
					#ifdef _MAIN_DEBUG_
					printf(">> DHCP %d Failed\r\n", my_dhcp_retry);
					#endif
					my_dhcp_retry = 0;
					DHCP_stop();      // if restart, recall DHCP_init()
					network_init();   // apply the default static network and print out netinfo to serial
				}
				break;
			default:
				break;
		}

    	/* LED Toggle every 1sec */
    	if((msTicks - prevTick) > led_msTick)
    	{
    		tmp = ~tmp;
    		xGPIOPinWrite( xGPIO_PORTA_BASE, xGPIO_PIN_0, tmp ); // LED#1 Blink
    		xGPIOPinWrite( xGPIO_PORTA_BASE, xGPIO_PIN_1, ~tmp ); // LED#2 Blink
    		prevTick = msTicks;
    	}
    } // end of Main loop
} // end of main()


void  wizchip_select(void)
{
   xGPIOPinWrite( xGPIO_PORTA_BASE, xGPIO_PIN_4, 0);
}

void  wizchip_deselect(void)
{
   xGPIOPinWrite( xGPIO_PORTA_BASE, xGPIO_PIN_4, 1);
}

void  wizchip_write(uint8_t wb)
{
   xSPISingleDataReadWrite(WIZCHIP_SPI_BASE,wb);
}

uint8_t wizchip_read()
{
   return xSPISingleDataReadWrite(WIZCHIP_SPI_BASE,0xFF);
}
