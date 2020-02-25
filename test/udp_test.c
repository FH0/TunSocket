#include <pthread.h>
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

void udp_cb(ts_data_t *data) {
    if (TS_UDP == data->type) {
        char buf[65535];
        char saddr[16];
        char daddr[16];
        struct sockaddr_in sendAddr;
        int nread;
        int udpFd;
        socklen_t sockLen;

        sockLen = sizeof(struct sockaddr_in);

        /* print something */
        inet_ntop(AF_INET, data->udp.sip, saddr, sockLen);
        inet_ntop(AF_INET, data->udp.dip, daddr, sockLen);
        printf("ipv4 udp %s:%d -> %s:%d \n", saddr, ntohs(data->udp.sport),
               daddr, ntohs(data->udp.dport));

        memset(&sendAddr, 0, sockLen);
        sendAddr.sin_family = AF_INET;
        sendAddr.sin_port = data->udp.dport;
        memcpy(&sendAddr.sin_addr.s_addr, data->udp.dip, 4);

        udpFd = socket(AF_INET, SOCK_DGRAM, 0);
        ASSERT(-1 != udpFd);

        sendto(udpFd, data->udp.buf, data->udp.bufLen, 0,
               (struct sockaddr *)&sendAddr, sockLen);
        nread = recvfrom(udpFd, buf, 65535, 0, (struct sockaddr *)&sendAddr,
                         &sockLen);

        ts_udp_write(TS_UDP, data->udp.dip, data->udp.dport, data->udp.sip,
                     data->udp.sport, buf, nread);
        close(udpFd);
    } else if (TS6_UDP == data->type) {
        char buf[65535];
        char saddr[40];
        char daddr[40];
        struct sockaddr_in6 sendAddr;
        int nread;
        int udpFd;
        socklen_t sockLen;

        sockLen = sizeof(struct sockaddr_in6);

        /* print something */
        inet_ntop(AF_INET6, data->udp.sip, saddr, 40);
        inet_ntop(AF_INET6, data->udp.dip, daddr, 40);
        printf("ipv6 udp %s:%d -> %s:%d \n", saddr, ntohs(data->udp.sport),
               daddr, ntohs(data->udp.dport));

        memset(&sendAddr, 0, sockLen);
        sendAddr.sin6_family = AF_INET6;
        sendAddr.sin6_port = data->udp.dport;
        memcpy(sendAddr.sin6_addr.s6_addr, data->udp.dip, 16);

        udpFd = socket(AF_INET6, SOCK_DGRAM, 0);
        ASSERT(-1 != udpFd);

        sendto(udpFd, data->udp.buf, data->udp.bufLen, 0,
               (struct sockaddr *)&sendAddr, sockLen);
        nread = recvfrom(udpFd, buf, 65535, 0, (struct sockaddr *)&sendAddr,
                         &sockLen);

        ts_udp_write(TS6_UDP, data->udp.dip, data->udp.dport, data->udp.sip,
                     data->udp.sport, buf, nread);
        close(udpFd);
    }
}

int main() {
    signal(SIGPIPE, SIG_IGN);

    // ts_set(TS_TUN_PATH, "/dev/tun");

    ts_init();

    ts_run(udp_cb);

    return 0;
}
