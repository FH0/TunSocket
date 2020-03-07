#ifndef TCP_H__VFH5Y
#define TCP_H__VFH5Y

#include <tunsocket.h>

void tcp_write(ts_data_t *data);
void handle_tcp(uint8_t flag, char *buf, int bufLen);
void handle_tcp_ack(ts_data_t *data, char flag);

/*
 * uint8_t recv_fin:1
 * uint8_t send_fin:1
 * uint8_t fin_when_wBufLen_zero_and_drop_recv:1 // ts_tcp_close() called
 * uint8_t rst:1 // serious problem, should be deleted in short time
 * uint8_t no_WBufLeft:1
 * uint8_t fin_when_wBufLen_zero:1 // ts_tcp_shutdown() called
 * uint8_t without_callback:1
 * uint8_t fin_cb_once:1
 */

#endif /* TCP_H__VFH5Y */