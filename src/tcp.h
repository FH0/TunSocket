#ifndef TCP_H__VFH5Y
#define TCP_H__VFH5Y

void tcp_write(ts_data_t *data);
void handle_tcp(uint16_t flag, char *buf, int bufLen);

/*
 * uint8_t recv_fin:1
 * uint8_t send_fin:1
 * uint8_t fin_when_wBufLen_zero:1 // ts_tcp_close() called
 * uint8_t rst:1 // serious problem, should be deleted in short time
 * uint8_t no_WBufLeft:1
 * uint8_t res:2
 */

#endif /* TCP_H__VFH5Y */