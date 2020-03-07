#include "event.h"
#include "misc.h"
#include "tcp.h"
#include "udp.h"

static char *unixPath = NULL;
static char *tunPath = "/dev/net/tun";
static char *tunName = "tun3";
static char *tunAddr = "10.5.5.5";
static char *tunAddr6 = "fd00::5";

uint32_t tcpRMax = 192 * 1024;
uint32_t tcpWMax = 192 * 1024;
ts_data_t *tcpHead;
int tunFd;
uint32_t tunMtu = 65535;

void (*ts_cb)(ts_data_t *data);

static void thread1_cb(void *arg);
static void thread2_cb(void *arg);

void ts_set(int flag, ...) {
    va_list ap;

    va_start(ap, flag);
    if (flag == TS_MTU) {
        tunMtu = va_arg(ap, uint32_t);
    } else if (flag == TS_UNIX_PATH) {
        unixPath = va_arg(ap, char *);
    } else if (flag == TS_TUN_PATH) {
        tunPath = va_arg(ap, char *);
    } else if (flag == TS_TUN_NAME) {
        tunName = va_arg(ap, char *);
    } else if (flag == TS_TCP_RMAX) {
        tcpRMax = va_arg(ap, uint32_t);
    } else if (flag == TS_TCP_WMAX) {
        tcpWMax = va_arg(ap, uint32_t);
    } else if (flag == TS_ADDR) {
        tunAddr = va_arg(ap, char *);
    } else if (flag == TS_ADDR6) {
        tunAddr6 = va_arg(ap, char *);
    } else {
        ASSERT(0 && "flag not support");
    }
    va_end(ap);
}

int ts_init() {
    /* open tun device, root needed */
    if (!unixPath) {
        struct ifreq ifr;

        tunFd = open(tunPath, O_RDWR);
        ASSERT(-1 != tunFd);

        /* set name */
        memset(&ifr, 0, sizeof(ifr));
        ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
        memcpy(ifr.ifr_name, tunName, IFNAMSIZ);
        ASSERT(-1 != (ioctl(tunFd, TUNSETIFF, &ifr)));

        /* set mtu */
        int sockFd = socket(AF_INET, SOCK_DGRAM, 0);
        ASSERT(-1 != sockFd);
        ifr.ifr_mtu = tunMtu;
        ASSERT(-1 != (ioctl(sockFd, SIOCSIFMTU, &ifr)));

        /* add ipv4 address */
        struct sockaddr_in sai;
        memset(&sai, 0, sizeof(struct sockaddr_in));
        sai.sin_family = AF_INET;
        inet_pton(AF_INET, tunAddr, &sai.sin_addr.s_addr);
        memcpy(&ifr.ifr_addr, &sai, sizeof(struct sockaddr_in));
        ASSERT(-1 != (ioctl(sockFd, SIOCSIFADDR, &ifr)));

        /* add ipv6 address */
        int sock6Fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_IP);
        ASSERT(-1 != sock6Fd);
        ASSERT(-1 != (ioctl(sock6Fd, SIOGIFINDEX, &ifr)));
        struct in6_ifreq ifr6;
        inet_pton(AF_INET6, tunAddr6, &ifr6.ifr6_addr);
        ifr6.ifr6_prefixlen = 64;
        ifr6.ifr6_ifindex = ifr.ifr_ifindex;
        ASSERT(-1 != (ioctl(sock6Fd, SIOCSIFADDR, &ifr6)));
        close(sock6Fd);

        /* link up */
        ifr.ifr_flags |= IFF_UP;
        ASSERT(-1 != (ioctl(sockFd, SIOCSIFFLAGS, &ifr)));
        close(sockFd);
    }
    /* get tun fd from unix domain socket */
    else {
        int unixSock;
        int connFd;
        struct sockaddr_un sun;
        int dummy = 0;
        char buf[CMSG_SPACE(sizeof(tunFd))];
        struct iovec iov;
        struct msghdr msg;
        struct cmsghdr *cmsg;

        unixSock = socket(PF_UNIX, SOCK_STREAM, 0);

        sun.sun_family = AF_UNIX;
        memcpy(sun.sun_path, unixPath, strlen(unixPath));

        ASSERT(-1 != (bind(unixSock, (struct sockaddr *)&sun, sizeof(sun))));
        ASSERT(-1 != (listen(unixSock, 5)));
        connFd = accept(unixSock, NULL, NULL);
        ASSERT(-1 != connFd);

        iov.iov_base = &dummy;
        iov.iov_len = 1;

        memset(&msg, 0, sizeof(msg));
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;
        msg.msg_control = buf;
        msg.msg_controllen = sizeof(buf);

        cmsg = CMSG_FIRSTHDR(&msg);
        cmsg->cmsg_len = CMSG_LEN(sizeof(tunFd));
        cmsg->cmsg_level = SOL_SOCKET;
        cmsg->cmsg_type = SCM_RIGHTS;

        memcpy(CMSG_DATA(cmsg), &tunFd, sizeof(tunFd));

        ASSERT(-1 != (recvmsg(connFd, &msg, 0)));

        memcpy(&tunFd, CMSG_DATA(cmsg), sizeof(tunFd));
        close(unixSock);
    }

    return tunFd;
}

static void thread1_cb(void *arg) {
    /* buffer to store data from tun, tunMtu as buffer size */
    char *buf = ts_malloc(tunMtu);

    /* buffer to store raw data and udp data */
    ts_data_t *data = ts_malloc(sizeof(ts_data_t));

    int bufLen;
    for (;;) {
        bufLen = read(tunFd, buf, tunMtu);

        /* handle data from tun */
        if (bufLen > 20) {
            if ((buf[0] >> 4) == 4) {
                if (buf[9] == 6) {
                    handle_tcp(4, buf, bufLen);
                } else if (buf[9] == 17) {
                    handle_udp(TS_UDP, data, buf, bufLen);

                    ts_cb(data);
                } else {
                    data->type = TS_RAW;
                    data->raw.buf = buf;
                    data->raw.bufLen = bufLen;

                    ts_cb(data);
                }
            } else if ((buf[0] >> 4) == 6) {
                if (buf[6] == 6) {
                    handle_tcp(6, buf, bufLen);
                } else if (buf[6] == 17) {
                    handle_udp(TS6_UDP, data, buf, bufLen);

                    ts_cb(data);
                } else {
                    data->type = TS6_RAW;
                    data->raw.buf = buf;
                    data->raw.bufLen = bufLen;

                    ts_cb(data);
                }
            }
        }
    }
}

static void thread2_cb(void *arg) {
    ts_data_t *data;
    for (;;) {
        for (data = tcpHead->tcp.next; data; data = data->tcp.next) {
            uint64_t nowTime = get_usec();
            if (data->tcp.timeout != 0 && nowTime > data->tcp.timeout) {
                if (data->type == TS_CONNECT || data->type == TS6_CONNECT)
                    handle_tcp_ack(data, 0x00); /* ack syn */
                else if (data->tcp.wBufLen > 0)
                    tcp_write(data);
                else if (data->tcp.wBufLen == 0)
                    handle_tcp_ack(data, 0x02); /* ack fin */
            }
        }
        usleep(100 * 1000); /* equal 100ms */
    }
}

void ts_run(void (*ts_cb_tmp)(ts_data_t *data)) {
    /* init tcp queue head */
    tcpHead = ts_malloc(sizeof(ts_data_t));

    /* convey function pointer */
    ts_cb = ts_cb_tmp;

    /* thread1 handle data form tun and callback */
    /* thread2 handle tcp timer */
    pthread_t thread1, thread2;
    pthread_create(&thread1, NULL, (void *)&thread1_cb, NULL);
    pthread_create(&thread2, NULL, (void *)&thread2_cb, NULL);
    pthread_join(thread1, NULL);
    pthread_join(thread1, NULL);
}
