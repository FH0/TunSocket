#include <errno.h>
#include <linux/sockios.h>
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

extern void save_to_file(char *file, char *buf, int bufLen);

int socket_send_left(int sockFd) {
    socklen_t intLen = sizeof(int);
    int sendMax, sendUsed;
    getsockopt(sockFd, SOL_SOCKET, SO_SNDBUF, &sendMax, &intLen);
    sendMax = sendMax / 2; /* linux cause this */
    ioctl(sockFd, SIOCOUTQ, &sendUsed);
    return sendMax - sendUsed;
}

int socket_recv_used(int sockFd) {
    int recvUsed;
    ioctl(sockFd, SIOCINQ, &recvUsed);
    return recvUsed;
}

int tcp_status(int sockFd) {
    struct tcp_info info;
    socklen_t len = sizeof(info);
    getsockopt(sockFd, IPPROTO_TCP, TCP_INFO, &info, &len);
    return info.tcpi_state;
}

void pinfo(char *hdr, char *ip1, char *ip2) {
    char addr1[16];
    char addr2[16];

    char *color;
    if (!(strcmp(hdr, "connect")))
        color = "\033[32m"; /* green */
    else if (!(strcmp(hdr, "payload")))
        color = "\033[33m"; /* yellow */
    else if (!(strcmp(hdr, "shutdown")))
        color = "\033[0m"; /* white */
    else if (!(strcmp(hdr, "close")))
        color = "\033[31m"; /* red */
    else if (!(strcmp(hdr, "error")))
        color = "\033[31m"; /* red */

    inet_ntop(AF_INET, ip1, addr1, 16);
    inet_ntop(AF_INET, ip2, addr2, 16);
    printf("%s%-10s\033[0m %-16s -> %-16s \n", color, hdr, addr1, addr2);
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
        socklen_t sockLen = sizeof(struct sockaddr_in);

        pinfo("connect", data->tcp.sip, data->tcp.dip);

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

        if (data->tcp.status & 0x10) {
            pinfo("error", data->tcp.sip, data->tcp.dip);
            epoll_ctl(epollFd, EPOLL_CTL_DEL, pData->fd,
                      (struct epoll_event *)NULL);
            close(pData->fd);
            ts_tcp_close(data);
            ts_free(data->tcp.ptr);
        } else if (data->tcp.rBufLen == 0) {
            if ((tcp_status(pData->fd)) == TCP_CLOSE_WAIT) {
                pinfo("close", data->tcp.dip, data->tcp.sip);
                epoll_ctl(epollFd, EPOLL_CTL_DEL, pData->fd,
                          (struct epoll_event *)NULL);
                close(pData->fd);
                ts_tcp_close(data);
                ts_free(pData);
            } else {
                pinfo("shutdown", data->tcp.sip, data->tcp.dip);
                shutdown(pData->fd, 1); /* close write stream */
            }
        } else {
            if ((tcp_status(pData->fd)) == TCP_SYN_SENT)
                return;

            pinfo("payload", data->tcp.sip, data->tcp.dip);
            int sendLeft = socket_send_left(pData->fd);
            int n = data->tcp.rBufLen;
            if (n <= sendLeft) {
                char tmp[n];
                ts_tcp_read(data, tmp, n);
                SILENT(write(pData->fd, tmp, n));
            } else {
                char tmp[sendLeft + 1];
                ts_tcp_read(data, tmp, sendLeft);
                SILENT(write(pData->fd, tmp, sendLeft + 1));
            }
        }
    } else if (data->type == TS_WABLE) {
        epoll_ptr_t *pData = (epoll_ptr_t *)data->tcp.ptr;
        int recvUsed = socket_recv_used(pData->fd);
        if (recvUsed <= 0)
            return;

        pinfo("payload", data->tcp.dip, data->tcp.sip);

        int wBufLeft = tcpWMax - data->tcp.wBufLen;
        if (recvUsed <= wBufLeft) {
            char tmp[recvUsed];
            SILENT(read(pData->fd, tmp, recvUsed));
            ts_tcp_write(data, tmp, recvUsed);
        } else {
            char tmp[wBufLeft + 1];
            SILENT(read(pData->fd, tmp, wBufLeft));
            ts_tcp_write(data, tmp, wBufLeft + 1);
        }
    }
}

void thread1_cb(void *arg) {
    ts_init();
    ts_run(tcp_cb);
}

void thread2_cb(void *arg) {
    struct epoll_event events[512];

    int i, number;
    for (;;) {
        number = epoll_wait(epollFd, events, 512, -1);
        ASSERT(-1 != number);

        for (i = 0; i < number; i++) {
            epoll_ptr_t *pData = (epoll_ptr_t *)events[i].data.ptr;
            ts_data_t *data = pData->data;
            if (events[i].events & EPOLLIN) {
                if (data == NULL)
                    puts("NULL");

                int recvUsed = socket_recv_used(pData->fd);
                if (recvUsed == 0) {
                    struct tcp_info info;
                    socklen_t len = sizeof(info);
                    getsockopt(pData->fd, IPPROTO_TCP, TCP_INFO, &info, &len);
                    if (info.tcpi_state == TCP_ESTABLISHED)
                        break; /* EAGAIN */

                    if ((info.tcpi_state == TCP_CLOSE_WAIT) &&
                        (!(data->tcp.status & 0x80))) {
                        ts_tcp_shutdown(data);
                        pinfo("shutdown", data->tcp.dip, data->tcp.sip);
                    } else {
                        pinfo("close", data->tcp.sip, data->tcp.dip);
                        ts_tcp_close(data);
                        epoll_ctl(epollFd, EPOLL_CTL_DEL, pData->fd,
                                  (struct epoll_event *)NULL);
                        close(pData->fd);
                        ts_free(events[i].data.ptr);
                    }
                    break;
                } else {
                    if (data->tcp.wBufLen >= tcpWMax)
                        break;

                    pinfo("payload", data->tcp.dip, data->tcp.sip);

                    int recvUsed = socket_recv_used(pData->fd);
                    int wBufLeft = tcpWMax - data->tcp.wBufLen;
                    if (recvUsed <= wBufLeft) {
                        char tmp[recvUsed];
                        SILENT(read(pData->fd, tmp, recvUsed));
                        // save_to_file("raw", tmp, recvUsed);
                        ts_tcp_write(data, tmp, recvUsed);
                    } else {
                        char tmp[wBufLeft + 1];
                        SILENT(read(pData->fd, tmp, wBufLeft));
                        // save_to_file("raw", tmp, wBufLeft);
                        ts_tcp_write(data, tmp, wBufLeft + 1);
                    }
                }
            } else if (events[i].events & EPOLLOUT) {
                int sendLeft = socket_send_left(pData->fd);
                if (data->tcp.rBufLen > 0) {
                    pinfo("payload", data->tcp.sip, data->tcp.dip);

                    int n = data->tcp.rBufLen;
                    printf("rBufLen %d\n", data->tcp.rBufLen);
                    if (n <= sendLeft) {
                        char tmp[n];
                        ts_tcp_read(data, tmp, n);
                        SILENT(write(pData->fd, tmp, n));
                    } else {
                        char tmp[sendLeft + 1];
                        ts_tcp_read(data, tmp, sendLeft);
                        SILENT(write(pData->fd, tmp, sendLeft + 1));
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
