#include <hardware/w5500/w5500_network.hpp>

void wizchip_reset(void);
void wizchip_select(void);
void wizchip_deselect(void);
void wizchip_write_byte(uint8_t wb);
uint8_t wizchip_read_byte(void);
//void wizchip_write_buf(uint8_t* pBuf, uint16_t len);
//void wizchip_read_buf(uint8_t* pBuf, uint16_t len);

int wizchip_socket_open(void);

uint8_t memsize[2][8] = { {2,2,2,2,2,2,2,2},{2,2,2,2,2,2,2,2}};
uint8_t udp_sock = 1;

//*********************************************************************************************************
int wiznet_init()
{

//*********************************************************************************************************
wiz_NetInfo gWIZNETINFO = {.mac = {0x00, 0x08, 0xdc, 0x00, 0xab, 0xcd},
                           .ip = {10, 0, 2, 123},
                           .sn = {255, 255, 255, 0},
                           .gw = {10, 0, 2, 1},
                           .dns = {8, 8, 8, 8},
                           .dhcp = NETINFO_STATIC};
  uint8_t tmpstr[6] = {0,  };
  wiz_NetInfo netinfo;
  
  pinMode(W5500_SS, OUTPUT);

    // Initialize SPI For W5500
  W5500_SPI.begin();
  W5500_SPI.beginTransaction(SPISettings(14000000, MSBFIRST, SPI_MODE0));
  
  // Reset W5500
  wizchip_reset();

  // Setting callback functions
  reg_wizchip_cs_cbfunc(wizchip_select, wizchip_deselect);
  reg_wizchip_spi_cbfunc(wizchip_read_byte, wizchip_write_byte);
  //reg_wizchip_spiburst_cbfunc(wizchip_read_buf, wizchip_write_buf);
    
  // Buffer init
  if (ctlwizchip(CW_INIT_WIZCHIP, (void *)memsize) == -1)
  {
    VS_LOG_ERROR("WIZCHIP Initialized fail.\r\n");
    while (1);
  }

  delay(100);

  // Set Network information from netinfo structure
	ctlnetwork(CN_SET_NETINFO, (void*)&gWIZNETINFO);

  // Get Network information
  ctlnetwork(CN_GET_NETINFO, (void*)&netinfo);
	// Display Network Information
	ctlwizchip(CW_GET_ID,(void*)tmpstr);
	if(netinfo.dhcp == NETINFO_DHCP) VS_LOG_INFO("=== %s NET CONF : DHCP ===",(char*)tmpstr);
	else VS_LOG_INFO("=== %s NET CONF : Static ===",(char*)tmpstr);
	VS_LOG_INFO("MAC: %02X:%02X:%02X:%02X:%02X:%02X",netinfo.mac[0],netinfo.mac[1],netinfo.mac[2],netinfo.mac[3],netinfo.mac[4],netinfo.mac[5]);
	VS_LOG_INFO("SIP: %d.%d.%d.%d", netinfo.ip[0],netinfo.ip[1],netinfo.ip[2],netinfo.ip[3]);
	VS_LOG_INFO("GAR: %d.%d.%d.%d", netinfo.gw[0],netinfo.gw[1],netinfo.gw[2],netinfo.gw[3]);
	VS_LOG_INFO("SUB: %d.%d.%d.%d", netinfo.sn[0],netinfo.sn[1],netinfo.sn[2],netinfo.sn[3]);
	VS_LOG_INFO("DNS: %d.%d.%d.%d", netinfo.dns[0],netinfo.dns[1],netinfo.dns[2],netinfo.dns[3]);
  VS_LOG_INFO("===========================");

  wizchip_socket_open();

  return 0;
}

//*********************************************************************************************************
int wizchip_socket_open(void) {
  int sock_err = 0;
  sock_err = socket(udp_sock,Sn_MR_UDP,W5500_UDP_PORT,SO_SENDBUF);
  
  VS_LOG_INFO( "socket %d opened", (udp_sock));
  /* Check socket register */
  VS_LOG_INFO( "socket state %d opened", getSn_SR(udp_sock));
  while(getSn_SR(udp_sock) !=SOCK_UDP);
  //while(getSn_SR(udp_sock) != SOCK_INIT);
  sock_err = listen(udp_sock);
  if( ! (sock_err & SOCK_OK) ) {
    VS_LOG_INFO( "socket error listening ERR:", sock_err );
    return sock_err;
  }
    
  wizchip_setinterruptmask(IK_SOCK_ALL);
  
  // Set int
  VS_LOG_INFO( "Sn_IMR: %d", getSn_IMR(udp_sock));
  setSn_IMR(udp_sock,( getSn_IMR(udp_sock) | Sn_IR_RECV));
  VS_LOG_INFO( "Sn_IMR: %d", getSn_IMR(udp_sock));

  VS_LOG_INFO( "Sn_IR: %d", getSn_IR(udp_sock));
  setSn_IR(udp_sock,(getSn_IR(udp_sock) ^ Sn_IR_RECV));
  VS_LOG_INFO( "Sn_IR: %d", getSn_IR(udp_sock));

  return sock_err;
}


//*********************************************************************************************************
 void wizchip_reset(void)
{
  VS_LOG_INFO("Withnet hardware reset");
  pinMode(W5500_RST, OUTPUT);
  digitalWrite(W5500_RST, LOW);
  delay(10);
  digitalWrite(W5500_RST, HIGH);
  delay(1000);
}
//*********************************************************************************************************
 void wizchip_select(void)
{
  digitalWrite(W5500_SS, LOW);
}
//*********************************************************************************************************
 void wizchip_deselect(void)
{
  digitalWrite(W5500_SS, HIGH);
}
//*********************************************************************************************************
 void wizchip_write_byte(uint8_t wb)
{
  W5500_SPI.transfer(wb, SPI_CONTINUE);
}
//*********************************************************************************************************
 uint8_t wizchip_read_byte(void)
{
  return (W5500_SPI.transfer(0xFF));
}

