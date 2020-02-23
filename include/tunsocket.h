#ifndef TUN_SOCKET_H__VFH5Y
#define TUN_SOCKET_H__VFH5Y

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <linux/ipv6.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

enum {
    TS_MTU = 1,
    TS_UNIX_PATH,
    TS_TUN_PATH,
    TS_TUN_NAME,
    TS_TCP_RMAX,
    TS_TCP_WMAX,
    TS_ADDR,
    TS_ADDR6,
    TS_TCP_ET
};

#define TS_CONNECT 0x01
#define TS_RABLE 0x02
#define TS_WABLE 0x03
#define TS_UDP 0x04
#define TS_RAW 0x05

#define TS6_CONNECT 0x10
#define TS6_RABLE 0x20
#define TS6_WABLE 0x30
#define TS6_UDP 0x40
#define TS6_RAW 0x50

typedef struct ts_data {
    char type;
    union {
        struct {
            char status;
            uint16_t window;
            char sip[16];
            char dip[16];
            uint16_t sport;
            uint16_t dport;
            char *rBuf;
            char *wBuf;
            int rBufLen;
            int wBufLen;
            int ack;
            int seq;
            struct ts_data *next;
            struct ts_data *last;
            void *ptr;
        } tcp;
        struct {
            char sip[16];
            char dip[16];
            uint16_t sport;
            uint16_t dport;
            char *buf;
            int bufLen;
        } udp;
        struct {
            char *buf;
            int bufLen;
        } raw;
    };
} ts_data_t;

#define ts_free(ptr)                                                           \
    do {                                                                       \
        free(ptr);                                                             \
        ptr = NULL;                                                            \
    } while (0)
void *ts_malloc(int len);
void ts_set(int flag, ...);
int ts_init();
void ts_run(void (*ts_cb)(ts_data_t *data));
int ts_tcp_read(ts_data_t *data, char *buf, int bufLen);
int ts_tcp_write(ts_data_t *data, char *buf, int bufLen);
void ts_tcp_close(ts_data_t *data);
void ts_udp_write(char flag, void *sip, uint16_t sport, void *dip,
                  uint16_t dport, void *buf, int bufLen);

#endif /* TUN_SOCKET_H__VFH5Y */
