
#ifndef GATEWAY_EVENT_GROUP_BIT_FLAGS_H
#define GATEWAY_EVENT_GROUP_BIT_FLAGS_H

// Shared flags (shared_events)
#define SNAP_INIT_FINITE_BIT EVENT_BIT(0)

// Firmware upgrade flags (message_bin)
#define NEW_FIRMWARE_HTTP_BIT EVENT_BIT(0)
#define NEW_FW_URL EVENT_BIT(1)
#define MSG_BIN_RECEIVE_BIT EVENT_BIT(2)

// Incoming data flags (incoming_data_event_group)
#define EID_WIFI EVENT_BIT(0)
#define EID_PLC EVENT_BIT(1)
#define EID_IPC EVENT_BIT(2)
#define EID_WIFI_RX EVENT_BIT(3)
#define EID_WS_RX EVENT_BIT(4)
#define EID_IOT_RX EVENT_BIT(5)

#define EID_BITS_ALL (EID_WIFI | EID_PLC | EID_IPC | EID_WIFI_RX | EID_WS_RX | EID_IOT_RX)

#endif // GATEWAY_EVENT_GROUP_BIT_FLAGS_H
