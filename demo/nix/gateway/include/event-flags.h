
#ifndef GATEWAY_EVENT_GROUP_BIT_FLAGS_H
#define GATEWAY_EVENT_GROUP_BIT_FLAGS_H

// Shared flags (shared_events)
#define SNAP_INIT_FINITE_BIT (1 << 0)

// Firmware upgrade flags (message_bin)
#define NEW_FIRMWARE_HTTP_BIT (1 << 0)
#define NEW_FW_URL (1 << 1)
#define MSG_BIN_RECEIVE_BIT (1 << 2)

// Incoming data flags (incoming_data_event_group)
#define EID_WIFI (1 << 0)
#define EID_PLC (1 << 1)
#define EID_IPC (1 << 2)
#define EID_WIFI_RX (1 << 3)
#define EID_WS_RX (1 << 4)
#define EID_IOT_RX (1 << 5)

#define EID_BITS_ALL (EID_WIFI | EID_PLC | EID_IPC | EID_WIFI_RX | EID_WS_RX | EID_IOT_RX)

#endif // GATEWAY_EVENT_GROUP_BIT_FLAGS_H
