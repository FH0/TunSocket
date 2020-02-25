#include <signal.h>
#include <tunsocket.h>

#define ASSERT(expr)                                                           \
    do {                                                                       \
        if (!(expr)) {                                                         \
            fprintf(stderr, "Assertion failed in %s on line %d: %s\n",         \
                    __FILE__, __LINE__, #expr);                                \
            perror("");                                                        \
            abort();                                                           \
        }                                                                      \
    } while (0)

void tcp_cb(ts_data_t *data) {
    if (data->type == TS_CONNECT) {
        struct sockaddr_in sendAddr;
        int *tcpFd = ts_malloc(sizeof(int));
        ;
        char saddr[16];
        char daddr[16];
        socklen_t sockLen;

        sockLen = sizeof(struct sockaddr_in);

        /* print something */
        inet_ntop(AF_INET, data->tcp.sip, saddr, sockLen);
        inet_ntop(AF_INET, data->tcp.dip, daddr, sockLen);
        printf("ipv4 tcp connect %s:%d -> %s:%d \n", saddr,
               ntohs(data->tcp.sport), daddr, ntohs(data->tcp.dport));

        *tcpFd = socket(AF_INET, SOCK_STREAM, 0);
        ASSERT(-1 != *tcpFd);

        memset(&sendAddr, 0, sockLen);
        sendAddr.sin_family = AF_INET;
        sendAddr.sin_port = data->tcp.dport;
        memcpy(&sendAddr.sin_addr.s_addr, data->tcp.dip, 4);

        ASSERT(-1 != (connect(*tcpFd, (struct sockaddr *)&sendAddr, sockLen)));

        data->tcp.ptr = tcpFd;
    } else if (data->type == TS_RABLE) {
        int *tcpFd = data->tcp.ptr;
        char buf[65535];
        char saddr[16];
        char daddr[16];
        int nread;

        inet_ntop(AF_INET, data->tcp.sip, saddr, 16);
        inet_ntop(AF_INET, data->tcp.dip, daddr, 16);

        nread = ts_tcp_read(data, buf, 65535);
        if ((nread <= 0) && (errno != EAGAIN)) {
            printf("ipv4 tcp close %s:%d -> %s:%d \n", saddr,
                   ntohs(data->tcp.sport), daddr, ntohs(data->tcp.dport));

            close(*tcpFd);
            ts_tcp_close(data);
            ts_free(tcpFd);

            return;
        }

        printf("ipv4 tcp %s:%d -> %s:%d \n", saddr, ntohs(data->tcp.sport),
               daddr, ntohs(data->tcp.dport));

        if (write(*tcpFd, buf, nread))
            ; /* make compiler happy */
        nread = read(*tcpFd, buf, 65535);

        ts_tcp_write(data, buf, nread);
    } else if (data->type == TS6_CONNECT) {
        struct sockaddr_in6 sendAddr;
        int *tcpFd = ts_malloc(sizeof(int));
        ;
        char saddr[40];
        char daddr[40];
        socklen_t sockLen;

        sockLen = sizeof(struct sockaddr_in6);

        /* print something */
        inet_ntop(AF_INET6, data->tcp.sip, saddr, 40);
        inet_ntop(AF_INET6, data->tcp.dip, daddr, 40);
        printf("ipv6 tcp connect %s:%d -> %s:%d \n", saddr,
               ntohs(data->tcp.sport), daddr, ntohs(data->tcp.dport));

        *tcpFd = socket(AF_INET6, SOCK_STREAM, 0);
        ASSERT(-1 != *tcpFd);

        memset(&sendAddr, 0, sockLen);
        sendAddr.sin6_family = AF_INET6;
        sendAddr.sin6_port = data->tcp.dport;
        memcpy(&sendAddr.sin6_addr.s6_addr, data->tcp.dip, 16);

        ASSERT(-1 != (connect(*tcpFd, (struct sockaddr *)&sendAddr, sockLen)));

        data->tcp.ptr = tcpFd;
    } else if (data->type == TS6_RABLE) {
        int *tcpFd = data->tcp.ptr;
        char buf[65535];
        char saddr[40];
        char daddr[40];
        int nread;

        inet_ntop(AF_INET6, data->tcp.sip, saddr, 40);
        inet_ntop(AF_INET6, data->tcp.dip, daddr, 40);

        nread = ts_tcp_read(data, buf, 65535);
        if ((nread <= 0) && (errno != EAGAIN)) {
            printf("ipv6 tcp close %s:%d -> %s:%d \n", saddr,
                   ntohs(data->tcp.sport), daddr, ntohs(data->tcp.dport));

            close(*tcpFd);
            ts_tcp_close(data);
            ts_free(tcpFd);

            return;
        }

        printf("ipv6 tcp %s:%d -> %s:%d \n", saddr, ntohs(data->tcp.sport),
               daddr, ntohs(data->tcp.dport));

        if (write(*tcpFd, buf, nread))
            ; /* make compiler happy */
        nread = read(*tcpFd, buf, 65535);

        ts_tcp_write(data, buf, nread);
    }
}

int main() {
    signal(SIGPIPE, SIG_IGN);

    // ts_set(TS_TUN_PATH, "/dev/tun");

    ts_init();

    ts_run(tcp_cb);

    return 0;
}
