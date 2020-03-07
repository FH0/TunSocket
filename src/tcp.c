#include "tcp.h"
#include "event.h"
#include "misc.h"

static ts_data_t *search_queue(uint8_t flag, char *buf);
static void tcp_remove(ts_data_t *data);
static void tcp_new(uint8_t flag, char *buf);
static void ack_rst(uint8_t flag, char *buf);

static inline void tcp_remove(ts_data_t *data) {
    data->tcp.last->tcp.next = data->tcp.next;
    if (data->tcp.next)
        data->tcp.next->tcp.last = data->tcp.last;

    ts_free(data->tcp.rBuf);
    ts_free(data->tcp.wBuf);
    ts_free(data);
}

static ts_data_t *search_queue(uint8_t flag, char *buf) {
    int iphdrLen = (flag == 4) ? (buf[0] & 0x0f) * 4 : 40;
    ts_data_t *data;
    for (data = tcpHead->tcp.next; data; data = data->tcp.next) {
        if (flag == 4) {
            if (data->tcp.sport == *(uint16_t *)&buf[iphdrLen] &&
                (memcmp(data->tcp.sip, &buf[12], 4)) == 0)
                return data;
        } else {
            if (data->tcp.sport == *(uint16_t *)&buf[iphdrLen] &&
                (memcmp(data->tcp.sip, &buf[8], 16)) == 0)
                return data;
        }
    }
    return NULL;
}

static void tcp_new(uint8_t flag, char *buf) {
    int iphdrLen = (flag == 4) ? (buf[0] & 0x0f) * 4 : 40;
    ts_data_t *data = ts_malloc(sizeof(ts_data_t));

    if (flag == 4) {
        data->type = TS_CONNECT;
        memcpy(data->tcp.sip, &buf[12], 4);
        memcpy(data->tcp.dip, &buf[16], 4);
    } else {
        data->type = TS6_CONNECT;
        memcpy(data->tcp.sip, &buf[8], 16);
        memcpy(data->tcp.dip, &buf[24], 16);
    }
    data->tcp.sport = *(uint16_t *)&buf[iphdrLen];
    data->tcp.dport = *(uint16_t *)&buf[iphdrLen + 2];
    data->tcp.rBuf = ts_malloc(tcpRMax);
    data->tcp.wBuf = ts_malloc(tcpWMax);
    data->tcp.rBufLen = 0;
    data->tcp.wBufLen = 0;
    data->tcp.rBufPointer = 0;
    data->tcp.wBufPointer = 0;
    data->tcp.mss = ntohs(*(uint16_t *)&buf[iphdrLen + 22]);
    data->tcp.ack = ntohl(*(int *)&buf[iphdrLen + 4]) + 1;
    data->tcp.status = 0x00;
    data->tcp.next = NULL;
    data->tcp.ptr = NULL;

    pthread_mutex_init(&data->tcp.rLock, NULL);
    pthread_mutex_init(&data->tcp.wLock, NULL);
    pthread_mutex_init(&data->tcp.seqLock, NULL);

    ts_data_t *tmp;
    for (tmp = tcpHead; tmp->tcp.next; tmp = tmp->tcp.next)
        ;
    tmp->tcp.next = data;
    data->tcp.last = tmp;

    handle_tcp_ack(data, 0x00); /* ack syn */

    ts_cb(data);
}

static void ack_rst(uint8_t flag, char *buf) {
    int iphdrLen = (flag == 4) ? (buf[0] & 0x0f) * 4 : 40;
    int tcphdrLen = 20;
    int bufTmpLen = iphdrLen + tcphdrLen;
    char bufTmp[bufTmpLen];

    if (flag == 4) {
        struct iphdr *ip = (struct iphdr *)&bufTmp[0];
        ip->version = 4;
        ip->ihl = 5;
        ip->tos = 0;
        ip->tot_len = htons(bufTmpLen);
        ip->id = 0;
        ip->frag_off = 0;
        ip->ttl = 64;
        ip->protocol = 6;
        ip->check = 0;
        memcpy(&ip->saddr, &buf[16], 4);
        memcpy(&ip->daddr, &buf[12], 4);
        ip->check = calculate_checksum((uint16_t *)ip, iphdrLen);
    } else {
        struct ip6_hdr *ip6 = (struct ip6_hdr *)&bufTmp[0];
        ip6->ip6_flow = htonl(6 << 28);
        ip6->ip6_plen = htons(20);
        ip6->ip6_nxt = 6;
        ip6->ip6_hlim = 64;
        memcpy(&ip6->ip6_src, &buf[24], 16);
        memcpy(&ip6->ip6_dst, &buf[8], 16);
    }

    struct tcphdr *tcp = (struct tcphdr *)&bufTmp[iphdrLen];
    tcp->source = *(uint16_t *)&buf[iphdrLen + 2];
    tcp->dest = *(uint16_t *)&buf[iphdrLen];
    tcp->seq = 0;
    tcp->ack_seq = htonl(ntohl(*(int *)&buf[iphdrLen + 4]) + 1);
    tcp->res1 = 0;
    tcp->doff = 20 / 4;
    ((char *)tcp)[13] = 0x14; /* ack rst */
    tcp->window = 0;
    tcp->check = 0;
    tcp->urg_ptr = 0;

    if (flag == 4) {
        char bufChecksum[12 + bufTmpLen - iphdrLen];
        memcpy(bufChecksum, &buf[16], 4);
        memcpy(&bufChecksum[4], &buf[12], 4);
        *(uint16_t *)&bufChecksum[8] = htons(6);
        *(uint16_t *)&bufChecksum[10] = htons(bufTmpLen - iphdrLen);
        memcpy(&bufChecksum[12], &bufTmp[iphdrLen], bufTmpLen - iphdrLen);
        tcp->check = calculate_checksum((uint16_t *)bufChecksum,
                                        12 + bufTmpLen - iphdrLen);
    } else {
        char bufChecksum[36 + bufTmpLen - iphdrLen];
        memcpy(bufChecksum, &buf[24], 16);
        memcpy(&bufChecksum[16], &buf[8], 16);
        *(uint16_t *)&bufChecksum[32] = htons(6);
        *(uint16_t *)&bufChecksum[34] = htons(bufTmpLen - iphdrLen);
        memcpy(&bufChecksum[36], &bufTmp[iphdrLen], bufTmpLen - iphdrLen);
        tcp->check = calculate_checksum((uint16_t *)bufChecksum,
                                        36 + bufTmpLen - iphdrLen);
    }

    SILENT(write(tunFd, bufTmp, bufTmpLen));
}

int ts_tcp_read(ts_data_t *data, char *buf, int bufLen) {
    pthread_mutex_lock(&data->tcp.rLock);
    int n = -1;
    errno = EINVAL;

    if (data->type == TS_RABLE || data->type == TS6_RABLE ||
        data->type == TS_WABLE || data->type == TS6_WABLE) {
        if (data->tcp.rBufLen > 0) {
            n = ring_copy_out(data->tcp.rBuf, tcpRMax, data->tcp.rBufPointer,
                              data->tcp.rBufLen, buf, bufLen);
            data->tcp.rBufLen -= n;
            data->tcp.rBufPointer = (data->tcp.rBufPointer + n) % tcpRMax;
        } else if (data->tcp.status == 0) {
            errno = EAGAIN;
        } else if (data->tcp.status & 0x80) {
            n = 0; /* closed by peer */
            errno = 0;
        } else if (data->tcp.status & 0x10) {
            errno = EPIPE; /* rst */
        } else if (data->tcp.status & 0x01) {
            errno = EBADF; /* not open for reading */
        }
    }

    pthread_mutex_unlock(&data->tcp.rLock);
    return n;
}

int ts_tcp_write(ts_data_t *data, char *buf, int bufLen) {
    if (bufLen == 0) {
        errno = 0;
        return 0;
    }

    pthread_mutex_lock(&data->tcp.rLock);
    int n = -1;
    errno = EINVAL;

    if ((data->type == TS_RABLE) || (data->type == TS6_RABLE) ||
        (data->type == TS_WABLE) || (data->type == TS6_WABLE)) {
        n = ring_input(data->tcp.wBuf, tcpWMax, data->tcp.wBufPointer,
                       &data->tcp.wBufLen, buf, bufLen);
        if (data->tcp.wBufLen == n && data->tcp.wBufLen > 0)
            tcp_write(data);
        if (n < bufLen)
            data->tcp.status |= 0x08; /* WABLE callback status */
    }

    pthread_mutex_unlock(&data->tcp.rLock);
    return n;
}

void ts_tcp_close(ts_data_t *data) {
    if ((data->type == TS_RABLE) || (data->type == TS6_RABLE)) {
        data->tcp.status |= 0x20;

        if ((data->tcp.status & 0xb0) == 0xb0 || data->tcp.status & 0x10)
            tcp_remove(data);
        else if (data->tcp.status & 0x80 && data->tcp.wBufLen == 0 &&
                 !(data->tcp.status & 0x40))
            handle_tcp_ack(data, 0x02); /* ack fin */
    }
}

void ts_tcp_shutdown(ts_data_t *data) {
    if ((data->type == TS_RABLE) || (data->type == TS6_RABLE)) {
        data->tcp.status |= 0x04;

        if (data->tcp.status & 0x80 && data->tcp.wBufLen == 0 &&
            !(data->tcp.status & 0x40))
            handle_tcp_ack(data, 0x02); /* ack fin */
    }
}

void handle_tcp(uint8_t flag, char *buf, int bufLen) {
    int iphdrLen = (flag == 4) ? (buf[0] & 0x0f) * 4 : 40;
    int tcpFlag = buf[iphdrLen + 13] & 0x3f;

    ts_data_t *data = search_queue(flag, buf);
    if (!data) {
        if (tcpFlag == 0x02)
            tcp_new(flag, buf);
        else if (!(tcpFlag & 0x04))
            ack_rst(flag, buf);
        return;
    }

    int tcphdrLen = (*(uint8_t *)&buf[iphdrLen + 12] >> 4) * 4;
    int payloadLen = bufLen - iphdrLen - tcphdrLen;
    uint32_t peerAck = ntohl(*(int *)&buf[iphdrLen + 8]);
    data->tcp.window = ntohs(*(uint16_t *)&buf[iphdrLen + 14]);

    /* handle payload */
    if (payloadLen > 0) {
        uint32_t peerSeq = ntohl(*(int *)&buf[iphdrLen + 4]);
        if (data->tcp.ack == peerSeq) {
            if (!(data->tcp.status & 0x20)) { /* ts_tcp_close, drop payload */
                ring_input(data->tcp.rBuf, tcpRMax, data->tcp.rBufPointer,
                           &data->tcp.rBufLen, &buf[iphdrLen + tcphdrLen],
                           payloadLen);
                ts_cb(data);
            }
            data->tcp.ack += payloadLen;
        }
        handle_tcp_ack(data, 0x01); /* ack */
    }
    /* retransmission or update info */
    if (data->tcp.wBufLen > 0) {
        if (data->tcp.peerAck == peerAck) {
            data->tcp.seq = data->tcp.peerAck;
            tcp_write(data);
        } else if (data->tcp.peerAck < peerAck && peerAck <= data->tcp.seq) {
            printf("peerAck %d data->tcp.peerAck %d wBufPointer %d seq %d "
                   "wBufLen %d \n",
                   peerAck, data->tcp.peerAck, data->tcp.wBufPointer,
                   data->tcp.seq, data->tcp.wBufLen);
            uint32_t len = peerAck - data->tcp.peerAck;
            data->tcp.wBufPointer = (data->tcp.wBufPointer + len) % tcpWMax;
            data->tcp.wBufLen -= len;
            data->tcp.peerAck = peerAck;
            if (data->tcp.wBufLen > 0)
                tcp_write(data);
            else if (data->tcp.wBufLen == 0)
                data->tcp.timeout = 0;
        }
    } else if (data->tcp.wBufLen == 0 && data->tcp.status & 0x40) {
        data->tcp.timeout = 0;
    }
    /* ack */
    if (tcpFlag & 0x10) {
        if (data->type == TS_CONNECT) {
            data->tcp.peerAck = ntohl(*(int *)&buf[iphdrLen + 8]);
            data->tcp.seq += 1;
            data->type = TS_RABLE;
            data->tcp.timeout = 0;
        } else if (data->type == TS6_CONNECT) {
            data->tcp.peerAck = ntohl(*(int *)&buf[iphdrLen + 8]);
            data->tcp.seq += 1;
            data->type = TS6_RABLE;
            data->tcp.timeout = 0;
        } else if (!(data->tcp.status & 0x40)) {
            if (data->tcp.status & 0x08 && !(data->tcp.status & 0x20)) {
                data->type = (flag == 4) ? TS_WABLE : TS6_WABLE;
                data->tcp.status &= ~0x08;
                ts_cb(data);
                data->type = (flag == 4) ? TS_RABLE : TS6_RABLE;
            } else if (data->tcp.status & 0x24 && data->tcp.wBufLen == 0) {
                handle_tcp_ack(data, 0x02); /* ack fin */
            }
        }
        /* sent ack fin and recieve ack, should be deleted */
        else if ((data->tcp.status & 0xc0) == 0xc0) {
            tcp_remove(data);
        }
    }
    /* fin */
    if (tcpFlag & 0x01) {
        data->tcp.status |= 0x80;
        data->tcp.ack += 1;
        handle_tcp_ack(data, 0x01); /* ack */
        if (data->tcp.status & 0x20)
            tcp_remove(data);
        else if (data->tcp.rBufLen == 0)
            ts_cb(data);
    }
    /* rst */
    if (tcpFlag & 0x04) {
        data->tcp.status = 0x10;
        ts_cb(data);
    }
    /* ignore other tcp flags  */
}

void tcp_write(ts_data_t *data) {
    pthread_mutex_lock(&data->tcp.seqLock);

    if (data->tcp.wBufLen == 0)
        goto out;
/* 25c978dae2518c3da9beec8aa9d2f3da */
    int detection = (data->tcp.window == 0) ? 1 : 0;
    uint16_t peerWindowLeft =
        data->tcp.peerAck + data->tcp.window - data->tcp.seq;
    uint32_t sendLeft = data->tcp.wBufLen + data->tcp.peerAck - data->tcp.seq;
    if (peerWindowLeft == 0 || sendLeft == 0)
        goto out; /* zero make no sense */
    int sendLen = (peerWindowLeft < sendLeft) ? peerWindowLeft : sendLeft;
    int sendTimes = sendLen / data->tcp.mss;
    sendTimes += (detection || sendLen % data->tcp.mss) ? 1 : 0;
    printf("sendLen %d peerAck %d window %d wBufLen %d  seq %d \n", sendLen,
           data->tcp.peerAck, data->tcp.window, data->tcp.wBufLen,
           data->tcp.seq);
    uint16_t window = ((tcpRMax - data->tcp.rBufLen) > 65535)
                          ? htons(65535)
                          : htons(tcpRMax - data->tcp.rBufLen);
    int p = data->tcp.wBufPointer + data->tcp.seq - data->tcp.peerAck;
    for (int i = 0; i < sendTimes; i++) {
        int iphdrLen = (data->type & 0x0f) ? 20 : 40;
        int tcphdrLen = 20;
        int payloadLen;
        if ((sendTimes - i) == 1) {
            if (detection)
                payloadLen = 0;
            else
                payloadLen = (sendLen % data->tcp.mss)
                                 ? (sendLen % data->tcp.mss)
                                 : data->tcp.mss;
        } else {
            payloadLen = data->tcp.mss;
        }
        int bufTmpLen = iphdrLen + tcphdrLen + payloadLen;
        char bufTmp[bufTmpLen];

        if (data->type & 0x0f) {
            struct iphdr *ip = (struct iphdr *)&bufTmp[0];
            ip->version = 4;
            ip->ihl = 5;
            ip->tos = 0;
            ip->tot_len = htons(bufTmpLen);
            ip->id = 0;
            ip->frag_off = 0;
            ip->ttl = 64;
            ip->protocol = 6;
            ip->check = 0;
            memcpy(&ip->saddr, data->tcp.dip, 4);
            memcpy(&ip->daddr, data->tcp.sip, 4);
            ip->check = calculate_checksum((uint16_t *)ip, iphdrLen);
        } else {
            struct ip6_hdr *ip6 = (struct ip6_hdr *)&bufTmp[0];
            ip6->ip6_flow = htonl(6 << 28);
            ip6->ip6_plen = htons(bufTmpLen - iphdrLen);
            ip6->ip6_nxt = 6;
            ip6->ip6_hlim = 64;
            memcpy(&ip6->ip6_src, data->tcp.dip, 16);
            memcpy(&ip6->ip6_dst, data->tcp.sip, 16);
        }

        struct tcphdr *tcp = (struct tcphdr *)&bufTmp[iphdrLen];
        tcp->source = data->tcp.dport;
        tcp->dest = data->tcp.sport;
        tcp->seq = htonl(data->tcp.seq);
        tcp->ack_seq = htonl(data->tcp.ack);
        tcp->res1 = 0;
        tcp->doff = 20 / 4;
        ((char *)tcp)[13] = 0x18; /* ack psh */
        tcp->window = window;
        tcp->check = 0;
        tcp->urg_ptr = 0;

        if (!(detection)) {
            ring_copy_out(data->tcp.wBuf, tcpWMax, p, payloadLen,
                          &bufTmp[iphdrLen + tcphdrLen], payloadLen);
            p = (p + payloadLen) % tcpWMax;
            // save_to_file("out", &bufTmp[iphdrLen + tcphdrLen], payloadLen);
            data->tcp.seq += payloadLen;
        }

        if (data->type & 0x0f) {
            char bufChecksum[12 + bufTmpLen - iphdrLen];
            memcpy(bufChecksum, data->tcp.dip, 4);
            memcpy(&bufChecksum[4], data->tcp.sip, 4);
            *(uint16_t *)&bufChecksum[8] = htons(6);
            *(uint16_t *)&bufChecksum[10] = htons(bufTmpLen - iphdrLen);
            memcpy(&bufChecksum[12], &bufTmp[iphdrLen], bufTmpLen - iphdrLen);
            tcp->check = calculate_checksum((uint16_t *)bufChecksum,
                                            12 + bufTmpLen - iphdrLen);
        } else {
            char bufChecksum[36 + bufTmpLen - iphdrLen];
            memcpy(bufChecksum, data->tcp.dip, 16);
            memcpy(&bufChecksum[16], data->tcp.sip, 16);
            *(uint16_t *)&bufChecksum[32] = htons(6);
            *(uint16_t *)&bufChecksum[34] = htons(bufTmpLen - iphdrLen);
            memcpy(&bufChecksum[36], &bufTmp[iphdrLen], bufTmpLen - iphdrLen);
            tcp->check = calculate_checksum((uint16_t *)bufChecksum,
                                            36 + bufTmpLen - iphdrLen);
        }

        SILENT(write(tunFd, bufTmp, bufTmpLen));
    }

    data->tcp.timeout = get_usec() + timeOut; /* update timer */
    goto out;

out:
    pthread_mutex_unlock(&data->tcp.seqLock);
}

void handle_tcp_ack(ts_data_t *data, char flag) {
    pthread_mutex_lock(&data->tcp.seqLock);

    int iphdrLen = (data->type & 0x0f) ? 20 : 40;
    int tcphdrLen = (0x00 == flag) ? 24 : 20;
    int bufTmpLen = iphdrLen + tcphdrLen;
    char bufTmp[bufTmpLen];

    if (data->type & 0x0f) {
        struct iphdr *ip = (struct iphdr *)&bufTmp[0];
        ip->version = 4;
        ip->ihl = 5;
        ip->tos = 0;
        ip->tot_len = htons(bufTmpLen);
        ip->id = 0;
        ip->frag_off = 0;
        ip->ttl = 64;
        ip->protocol = 6;
        ip->check = 0;
        memcpy(&ip->saddr, data->tcp.dip, 4);
        memcpy(&ip->daddr, data->tcp.sip, 4);
        ip->check = calculate_checksum((uint16_t *)ip, iphdrLen);
    } else {
        struct ip6_hdr *ip6 = (struct ip6_hdr *)&bufTmp[0];
        ip6->ip6_flow = htonl(6 << 28);
        ip6->ip6_plen = htons(bufTmpLen - iphdrLen);
        ip6->ip6_nxt = 6;
        ip6->ip6_hlim = 64;
        memcpy(&ip6->ip6_src, data->tcp.dip, 16);
        memcpy(&ip6->ip6_dst, data->tcp.sip, 16);
    }

    struct tcphdr *tcp = (struct tcphdr *)&bufTmp[iphdrLen];
    tcp->source = data->tcp.dport;
    tcp->dest = data->tcp.sport;
    tcp->seq = htonl(data->tcp.seq);
    tcp->ack_seq = htonl(data->tcp.ack);
    tcp->res1 = 0;
    tcp->doff = tcphdrLen / 4;
    if (flag == 0x00) {
        ((char *)tcp)[13] = 0x12; /* ack syn */
        data->tcp.timeout = get_usec() + timeOut;
    } else if (flag == 0x01) {
        ((char *)tcp)[13] = 0x10; /* ack */
    } else if (flag == 0x02) {
        ((char *)tcp)[13] = 0x11; /* ack fin */
        data->tcp.timeout = get_usec() + timeOut;
        if (!(data->tcp.status & 0x40)) {
            data->tcp.status |= 0x40;
            data->tcp.seq += 1;
        }
    }
    if ((tcpRMax - data->tcp.rBufLen) > 65535)
        tcp->window = htons(65535);
    else
        tcp->window = htons(tcpRMax - data->tcp.rBufLen);
    tcp->check = 0;
    tcp->urg_ptr = 0;

    /* tcp mss */
    if (flag == 0x00)
        *(int *)&bufTmp[iphdrLen + tcphdrLen - 4] =
            htonl(0x02040000 + data->tcp.mss);

    if (data->type & 0x0f) {
        char bufChecksum[12 + tcphdrLen];
        memcpy(bufChecksum, data->tcp.dip, 4);
        memcpy(&bufChecksum[4], data->tcp.sip, 4);
        *(uint16_t *)&bufChecksum[8] = htons(6);
        *(uint16_t *)&bufChecksum[10] = htons(bufTmpLen - iphdrLen);
        memcpy(&bufChecksum[12], &bufTmp[iphdrLen], tcphdrLen);
        tcp->check =
            calculate_checksum((uint16_t *)bufChecksum, 12 + tcphdrLen);
    } else {
        char bufChecksum[36 + tcphdrLen];
        memcpy(bufChecksum, data->tcp.dip, 16);
        memcpy(&bufChecksum[16], data->tcp.sip, 16);
        *(uint16_t *)&bufChecksum[32] = htons(6);
        *(uint16_t *)&bufChecksum[34] = htons(bufTmpLen - iphdrLen);
        memcpy(&bufChecksum[36], &bufTmp[iphdrLen], tcphdrLen);
        tcp->check =
            calculate_checksum((uint16_t *)bufChecksum, 36 + tcphdrLen);
    }

    SILENT(write(tunFd, bufTmp, bufTmpLen));
    pthread_mutex_unlock(&data->tcp.seqLock);
}
