#include <errno.h>
#include <linux/sockios.h>
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
#define SILENT(ptr) (void)((ptr) + 1);

int socket_send_left(int sockFd) {
    socklen_t intLen = sizeof(int);
    int sendMax, sendUsed;
    ASSERT(-1 !=
           (getsockopt(sockFd, SOL_SOCKET, SO_SNDBUF, &sendMax, &intLen)));
    sendMax = sendMax / 2; /* linux cause this */
    ASSERT(-1 != (ioctl(sockFd, SIOCOUTQ, &sendUsed)));
    return sendMax - sendUsed;
}

int socket_recv_used(int sockFd) {
    int recvUsed;
    ASSERT(-1 != (ioctl(sockFd, SIOCINQ, &recvUsed)));
    return recvUsed;
}

int tcp_status(int sockFd) {
    struct tcp_info info;
    socklen_t len = sizeof(info);
    ASSERT(-1 != (getsockopt(sockFd, IPPROTO_TCP, TCP_INFO, &info, &len)));
    return info.tcpi_state;
}

typedef struct {
    int fd;
    ts_data_t *data;
} epoll_ptr_t;

static int epollFd;
static int tcpWMax =
    192 *
    1024; /* default is this, you should change it if you reset the value */

void epoll_add_fd(void *ptr) {
    struct epoll_event event;
    event.data.ptr = ptr;
    event.events = EPOLLIN | EPOLLOUT | EPOLLET;
    epoll_ctl(epollFd, EPOLL_CTL_ADD, ((epoll_ptr_t *)ptr)->fd, &event);
    ASSERT(-1 !=
           (fcntl(((epoll_ptr_t *)ptr)->fd, F_SETFL,
                  fcntl(((epoll_ptr_t *)ptr)->fd, F_GETFL) | O_NONBLOCK)));
}

void tcp_cb(ts_data_t *data) {
    if (data->type == TS_CONNECT) {
        struct sockaddr_in sendAddr;
        epoll_ptr_t *pData = ts_malloc(sizeof(epoll_ptr_t));

        char saddr[16];
        char daddr[16];
        socklen_t sockLen;

        sockLen = sizeof(struct sockaddr_in);

        /* print something */
        inet_ntop(AF_INET, data->tcp.sip, saddr, 16);
        inet_ntop(AF_INET, data->tcp.dip, daddr, 16);
                    printf("%-10s %-16s -> %-16s \n", "connect", saddr, daddr);

        pData->fd = socket(AF_INET, SOCK_STREAM, 0);
        ASSERT(-1 != pData->fd);
        pData->data = data;
        epoll_add_fd(pData);

        memset(&sendAddr, 0, sockLen);
        sendAddr.sin_family = AF_INET;
        sendAddr.sin_port = data->tcp.dport;
        memcpy(&sendAddr.sin_addr.s_addr, data->tcp.dip, 4);

        ASSERT((-1 !=
                (connect(pData->fd, (struct sockaddr *)&sendAddr, sockLen))) ||
               (errno == EINPROGRESS));

        data->tcp.ptr = pData;
    } else if (data->type == TS_RABLE) {
        epoll_ptr_t *pData = (epoll_ptr_t *)data->tcp.ptr;
        char saddr[16];
        char daddr[16];

        inet_ntop(AF_INET, data->tcp.sip, saddr, 16);
        inet_ntop(AF_INET, data->tcp.dip, daddr, 16);

        if (data->tcp.rBufLen <= 0) {
            if ((tcp_status(pData->fd)) == TCP_CLOSE_WAIT) {
                printf("%-10s %-16s -> %-16s \n", "close", saddr, daddr);
                epoll_ctl(epollFd, EPOLL_CTL_DEL, pData->fd,
                          (struct epoll_event *)NULL);
                close(pData->fd);
                ts_tcp_close(data);
                ts_free(pData);
            } else {
                printf("%-10s %-16s -> %-16s \n", "shutdown", saddr, daddr);
                shutdown(pData->fd, 1); /* close write stream */
            }
        } else if (data->tcp.status & 0x10) {
            printf("%-10s %-16s -> %-16s \n", "error", saddr, daddr);
            epoll_ctl(epollFd, EPOLL_CTL_DEL, pData->fd,
                      (struct epoll_event *)NULL);
            close(pData->fd);
            ts_tcp_close(data);
            ts_free(data->tcp.ptr);
        } else {
            if ((tcp_status(pData->fd)) == TCP_SYN_SENT) {
                return;
            }
            printf("%-10s %-16s -> %-16s \n", "payload", saddr, daddr);
            int sendLeft = socket_send_left(pData->fd);
            if (sendLeft > 0) {
                int n = (sendLeft > data->tcp.rBufLen)
                            ? data->tcp.rBufLen
                            : sendLeft; /* how much data need to handle */
                char tmp[n];
                ts_tcp_read(data, tmp, n);
                SILENT(write(pData->fd, tmp, n));
                if (sendLeft <= data->tcp.rBufLen) { /* make it EAGAIN */
                    SILENT(write(pData->fd, "1", 1));
                }
            }
        }
    } else if (data->type == TS_WABLE) {
        epoll_ptr_t *pData = (epoll_ptr_t *)data->tcp.ptr;
        int recvUsed = socket_recv_used(pData->fd);
        if (recvUsed <= 0) {
            return;
        }

        char saddr[16];
        char daddr[16];

        inet_ntop(AF_INET, data->tcp.sip, saddr, 16);
        inet_ntop(AF_INET, data->tcp.dip, daddr, 16);

        printf("%-10s %-16s -> %-16s \n", "payload", daddr, saddr);

        int wBufLeft = tcpWMax - data->tcp.wBufLen;
        int n = (wBufLeft > recvUsed)
                    ? recvUsed
                    : wBufLeft; /* how much data need to handle */
        char tmp[n];
        SILENT(read(pData->fd, tmp, n));
        ts_tcp_write(data, tmp, n);
        if (wBufLeft <= recvUsed) {
            ts_tcp_write(data, "1", 1); /* make it EAGAIN */
        }
    } else if (data->type == TS6_CONNECT) {
        struct sockaddr_in6 sendAddr;
        epoll_ptr_t *pData = ts_malloc(sizeof(epoll_ptr_t));

        char saddr[40];
        char daddr[40];
        socklen_t sockLen;

        sockLen = sizeof(struct sockaddr_in6);

        /* print something */
        inet_ntop(AF_INET6, data->tcp.sip, saddr, 40);
        inet_ntop(AF_INET6, data->tcp.dip, daddr, 40);
        printf("%-10s %-16s -> %-16s \n", "connect", saddr, daddr);

        pData->fd = socket(AF_INET6, SOCK_STREAM, 0);
        ASSERT(-1 != pData->fd);
        pData->data = data;
        epoll_add_fd(pData);

        memset(&sendAddr, 0, sockLen);
        sendAddr.sin6_family = AF_INET6;
        sendAddr.sin6_port = data->tcp.dport;
        memcpy(&sendAddr.sin6_addr.s6_addr, data->tcp.dip, 16);

        ASSERT(-1 !=
               (connect(pData->fd, (struct sockaddr *)&sendAddr, sockLen)));

        data->tcp.ptr = pData;
    } else if (data->type == TS6_RABLE) {
        epoll_ptr_t *pData = (epoll_ptr_t *)data->tcp.ptr;
        char saddr[40];
        char daddr[40];

        inet_ntop(AF_INET6, data->tcp.sip, saddr, 40);
        inet_ntop(AF_INET6, data->tcp.dip, daddr, 40);

        if (data->tcp.rBufLen <= 0) {
            if ((tcp_status(pData->fd)) == TCP_CLOSE_WAIT) {
                epoll_ctl(epollFd, EPOLL_CTL_DEL, pData->fd,
                          (struct epoll_event *)NULL);
                close(pData->fd);
                ts_tcp_close(data);
                ts_free(pData);
            } else {
                shutdown(pData->fd, 1); /* close write stream */
            }
            printf("%-10s %-16s -> %-16s \n", "close", saddr, daddr);
        } else if (data->tcp.status & 0x10) {
            printf("%-10s %-16s -> %-16s \n", "error", saddr, daddr);
            epoll_ctl(epollFd, EPOLL_CTL_DEL, pData->fd,
                      (struct epoll_event *)NULL);
            close(pData->fd);
            ts_tcp_close(data);
            ts_free(data->tcp.ptr);
        } else {
            if ((tcp_status(pData->fd)) == TCP_SYN_SENT) {
                return;
            }
            printf("%-10s %-16s -> %-16s \n", "payload", saddr, daddr);
            int sendLeft = socket_send_left(pData->fd);
            if (sendLeft > 0) {
                int n = (sendLeft > data->tcp.rBufLen)
                            ? data->tcp.rBufLen
                            : sendLeft; /* how much data need to handle */
                char tmp[n];
                ts_tcp_read(data, tmp, n);
                SILENT(write(pData->fd, tmp, n));
                if (sendLeft <= data->tcp.rBufLen) { /* make it EAGAIN */
                    SILENT(write(pData->fd, "1", 1));
                }
            }
        }
    } else if (data->type == TS6_WABLE) {
        epoll_ptr_t *pData = (epoll_ptr_t *)data->tcp.ptr;
        int recvUsed = socket_recv_used(pData->fd);
        if ((socket_recv_used(((epoll_ptr_t *)data->tcp.ptr)->fd)) <= 0) {
            return;
        }

        char saddr[40];
        char daddr[40];

        inet_ntop(AF_INET, data->tcp.sip, saddr, 40);
        inet_ntop(AF_INET, data->tcp.dip, daddr, 40);

        printf("%-10s %-16s -> %-16s \n", "payload", daddr, saddr);

        int wBufLeft = tcpWMax - data->tcp.wBufLen;
        int n = (wBufLeft > recvUsed)
                    ? recvUsed
                    : wBufLeft; /* how much data need to handle */
        char tmp[n];
        SILENT(read(pData->fd, tmp, n));
        ts_tcp_write(data, tmp, n);
        if (wBufLeft <= recvUsed) {
            ts_tcp_write(data, "1", 1); /* make it EAGAIN */
        }
    }
}

void thread1_cb(void *arg) {
    ts_set(TS_TCP_ET);
    ts_init();
    ts_run(tcp_cb);
}

void thread2_cb(void *arg) {
    struct epoll_event events[512];

    for (;;) {
        int number = epoll_wait(epollFd, events, 512, -1);
        ASSERT(-1 != number);

        for (int i = 0; i < number; i++) {
            epoll_ptr_t *pData = (epoll_ptr_t *)events[i].data.ptr;
            ts_data_t *data = pData->data;
            if (events[i].events & EPOLLIN) {
                char saddr[16];
                char daddr[16];

                inet_ntop(AF_INET, data->tcp.sip, saddr, 16);
                inet_ntop(AF_INET, data->tcp.dip, daddr, 16);

                int recvUsed = socket_recv_used(pData->fd);
                if (recvUsed == 0) {
                    struct tcp_info info;
                    socklen_t len = sizeof(info);
                    getsockopt(pData->fd, IPPROTO_TCP, TCP_INFO, &info, &len);
                    if (info.tcpi_state == TCP_ESTABLISHED) {
                        break; /* EAGAIN */
                    }
                    printf("%-10s %-16s -> %-16s \n", "close", saddr, daddr);
                    if ((info.tcpi_state == TCP_CLOSE_WAIT) &&
                        (!(data->tcp.status & 0x80))) {
                        ts_tcp_shutdown(data);
                    } else {
                        ts_tcp_close(data);
                        epoll_ctl(epollFd, EPOLL_CTL_DEL, pData->fd,
                                  (struct epoll_event *)NULL);
                        close(pData->fd);
                        ts_free(events[i].data.ptr);
                    }
                    break;
                } else {
                    if (data->tcp.wBufLen >= tcpWMax) {
                        break;
                    }

                    printf("%-10s %-16s -> %-16s \n", "payload", daddr, saddr);

                    int recvUsed = socket_recv_used(pData->fd);
                    printf("%srecvUsed %d%s\n", "\033[36m", recvUsed, "\033[0m");
                    int wBufLeft = tcpWMax - data->tcp.wBufLen;
                    int n = (wBufLeft > recvUsed)
                                ? recvUsed
                                : wBufLeft; /* how much data need to
                                               handle */
                    char tmp[n];
                    SILENT(read(pData->fd, tmp, n));

                    ts_tcp_write(data, tmp, n);
                    if (wBufLeft <= recvUsed) {
                        ts_tcp_write(data, "1", 1); /* make it EAGAIN */
                    }
                }
            } else if (events[i].events & EPOLLOUT) {
                char saddr[16];
                char daddr[16];

                inet_ntop(AF_INET, data->tcp.sip, saddr, 16);
                inet_ntop(AF_INET, data->tcp.dip, daddr, 16);

                int sendLeft = socket_send_left(pData->fd);
                if (data->tcp.rBufLen > 0) {
                    printf("%-10s %-16s -> %-16s \n", "payload", saddr, daddr);

                    int n = (sendLeft > data->tcp.rBufLen)
                                ? data->tcp.rBufLen
                                : sendLeft; /* how much data need to handle */
                    char tmp[n];
                    ts_tcp_read(data, tmp, n);
                    SILENT(write(pData->fd, tmp, n));
                    if (sendLeft <= data->tcp.rBufLen) { /* make it EAGAIN */
                        SILENT(write(pData->fd, "1", 1));
                    }
                }
            } else {
                printf("epoll else\n");
            }
        }
    }
}

int main() {
    signal(SIGPIPE, SIG_IGN);

    epollFd = epoll_create1(EPOLL_CLOEXEC);
    ASSERT(-1 != epollFd);

    pthread_t thread1, thread2;
    pthread_create(&thread1, NULL, (void *)&thread1_cb, NULL);
    pthread_create(&thread2, NULL, (void *)&thread2_cb, NULL);
    pthread_join(thread1, NULL);
    pthread_join(thread2, NULL);

    return 0;
}
