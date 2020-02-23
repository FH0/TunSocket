#include <tunsocket.h>
#include "event.h"
#include "tcp.h"
#include "misc.h"

static void handle_tcp_ack(ts_data_t *data, char flag);

int ts_tcp_read(ts_data_t *data, char *buf, int bufLen)
{
    int n = -1;
    errno = EINVAL;

    if ((data->type == TS_RABLE) ||
        (data->type == TS6_RABLE))
    {
        if (data->tcp.rBufLen > 0)
        {
            n = (bufLen > data->tcp.rBufLen) ? data->tcp.rBufLen : bufLen;
            errno = 0;

            memcpy(buf, data->tcp.rBuf, n);

            memmove(data->tcp.rBuf, data->tcp.rBuf + n, data->tcp.rBufLen - n);
            data->tcp.rBufLen -= n;
        }
        else if (data->tcp.status == 0)
        {
            errno = EAGAIN;
        }
        else if (data->tcp.status & 0xe0)
        {
            n = 0; /* closed by peer */
            errno = 0;
        }
        else if (data->tcp.status & 0x10)
        {
            errno = EPIPE; /* ack rst */
        }
    }

    return n;
}

int ts_tcp_write(ts_data_t *data, char *buf, int bufLen)
{
    int n = -1;
    errno = EINVAL;

    if ((data->type == TS_RABLE) ||
        (data->type == TS6_RABLE) ||
        (data->type == TS_WABLE) ||
        (data->type == TS6_WABLE))
    {
        n = tcpWMax - data->tcp.wBufLen; /* n means buffer left */
        errno = 0;

        if (n <= 0)
        {
            data->tcp.status |= 0x08;
            errno = EAGAIN;
            return -1;
        }
        else if (n < bufLen)
        {
            memcpy(&data->tcp.wBuf[data->tcp.wBufLen], buf, n);
            data->tcp.wBufLen = tcpWMax;
        }
        else
        {
            n = bufLen;
            memcpy(&data->tcp.wBuf[data->tcp.wBufLen], buf, n);
            data->tcp.wBufLen += n;
        }

        tcp_write(data);
    }

    return n;
}

void ts_tcp_close(ts_data_t *data)
{
    if ((data->type == TS_RABLE) ||
        (data->type == TS6_RABLE))
    {
        data->tcp.status |= 0x20;

        if ((data->tcp.status & 0x80) &&
            (data->tcp.wBufLen <= 0))
        {
            handle_tcp_ack(data, 0x02); /* ack fin */
            data->tcp.status |= 0x40;
        }
    }
}

void handle_tcp(uint16_t flag, char *buf, int bufLen)
{
    int iphdrLen = (flag == 4) ? (buf[0] & 0x0f) * 4 : 40;
    ts_data_t *tmp;
    int tcpFlag = buf[iphdrLen + 13] & 0x3f;
    uint16_t peerWindow = ntohs(*(uint16_t *)&buf[iphdrLen + 14]);

    /* search in tcp queue */
    for (tmp = tcpHead->tcp.next; tmp; tmp = tmp->tcp.next)
    {
        if (flag == 4)
        {
            if ((tmp->tcp.sport != *(uint16_t *)&buf[iphdrLen]) ||
                (0 != (memcmp(tmp->tcp.sip, &buf[12], 4))))
            {
                continue;
            }
        }
        else
        {
            if ((tmp->tcp.sport != *(uint16_t *)&buf[iphdrLen]) ||
                (0 != (memcmp(tmp->tcp.sip, &buf[8], 16))))
            {
                continue;
            }
        }

        int tcphdrLen = (*(uint8_t *)&buf[iphdrLen + 12] >> 4) * 4;
        int payloadLen = bufLen - iphdrLen - tcphdrLen;

        /* ack with payload */
        if (payloadLen)
        {
            tmp->tcp.ack = htonl(ntohl(*(int *)&buf[iphdrLen + 4]) + payloadLen);
            tmp->tcp.seq = htonl(ntohl(*(int *)&buf[iphdrLen + 8]));
            if (!(tmp->tcp.status & 0xf0))
            {
                tmp->tcp.window = peerWindow;
                memcpy(&tmp->tcp.rBuf[tmp->tcp.rBufLen], &buf[iphdrLen + tcphdrLen], payloadLen);
                tmp->tcp.rBufLen += payloadLen;
            }

            handle_tcp_ack(tmp, 0x01); /* ack */

            if ((tcpET == 1) &&
                (!(tmp->tcp.status & 0xf0)))
            {
                ts_cb(tmp);
            }
        }
        /* ack */
        else if (tcpFlag == 0x10)
        {
            if (tmp->type == TS_CONNECT)
            {
                tmp->type = TS_RABLE;
                tmp->tcp.ack = htonl(ntohl(*(int *)&buf[iphdrLen + 4]));
                tmp->tcp.seq = htonl(ntohl(*(int *)&buf[iphdrLen + 8]));
                tmp->tcp.window = peerWindow;
            }
            if (tmp->type == TS6_CONNECT)
            {
                tmp->type = TS6_RABLE;
                tmp->tcp.ack = htonl(ntohl(*(int *)&buf[iphdrLen + 4]));
                tmp->tcp.seq = htonl(ntohl(*(int *)&buf[iphdrLen + 8]));
                tmp->tcp.window = peerWindow;
            }
            else if (!(tmp->tcp.status & 0x40))
            {
                tmp->tcp.ack = htonl(ntohl(*(int *)&buf[iphdrLen + 4]));
                tmp->tcp.seq = htonl(ntohl(*(int *)&buf[iphdrLen + 8]));
                tmp->tcp.window = peerWindow;

                if (tmp->tcp.wBufLen > 0)
                {
                    tcp_write(tmp);

                    if (tmp->tcp.status & 0x08)
                    {
                        tmp->type = (flag == 4) ? TS_WABLE : TS6_WABLE;
                        tmp->tcp.status &= ~0x08;
                        ts_cb(tmp);
                        tmp->type = (flag == 4) ? TS_RABLE : TS6_RABLE;
                    }
                }
                else if (tmp->tcp.status & 0x20)
                {
                    handle_tcp_ack(tmp, 0x02); /* ack fin */
                    tmp->tcp.status |= 0x40;
                }
            }
            /* sent ack fin and recieve ack, should be deleted */
            else if ((tmp->tcp.status & 0xc0) == 0xc0)
            {
                puts("del");
                tmp->tcp.last->tcp.next = tmp->tcp.next;
                if (tmp->tcp.next)
                {
                    tmp->tcp.next->tcp.last = tmp->tcp.last;
                }
                ts_free(tmp->tcp.rBuf);
                ts_free(tmp->tcp.wBuf);
                ts_free(tmp);
            }
        }
        /* ack fin */
        else if (tcpFlag == 0x11)
        {
            tmp->tcp.status |= 0x80;
            tmp->tcp.ack = htonl(ntohl(*(int *)&buf[iphdrLen + 4]) + 1);
            tmp->tcp.seq = htonl(ntohl(*(int *)&buf[iphdrLen + 8]));

            handle_tcp_ack(tmp, 0x01); /* ack */

            if (tmp->tcp.status & 0x40)
            { /* ack fin sent already */
                tmp->tcp.last->tcp.next = tmp->tcp.next;
                if (tmp->tcp.next)
                {
                    tmp->tcp.next->tcp.last = tmp->tcp.last;
                }
                ts_free(tmp->tcp.rBuf);
                ts_free(tmp->tcp.wBuf);
                ts_free(tmp);
            }
            else if (tcpET == 1)
            {
                ts_cb(tmp);
            }
        }
        /* ack rst */
        else if (tcpFlag == 0x14)
        {
            tmp->tcp.status = 0x10;

            ts_cb(tmp);

            tmp->tcp.last->tcp.next = tmp->tcp.next;
            if (tmp->tcp.next)
            {
                tmp->tcp.next->tcp.last = tmp->tcp.last;
            }
            ts_free(tmp->tcp.rBuf);
            ts_free(tmp->tcp.wBuf);
            ts_free(tmp);
        }
        /* other tcp flags are ignored */

        return;
    }

    /* syn and add to tcp queue */
    if (tcpFlag == 0x02)
    {
        ts_data_t *data = ts_malloc(sizeof(ts_data_t));

        if (flag == 4)
        {
            data->type = TS_CONNECT;
            memcpy(data->tcp.sip, &buf[12], 4);
            memcpy(data->tcp.dip, &buf[16], 4);
        }
        else
        {
            data->type = TS6_CONNECT;
            memcpy(data->tcp.sip, &buf[8], 16);
            memcpy(data->tcp.dip, &buf[24], 16);
        }
        data->tcp.sport = *(uint16_t *)&buf[iphdrLen];
        data->tcp.dport = *(uint16_t *)&buf[iphdrLen + 2];
        data->tcp.rBufLen = 0;
        data->tcp.rBuf = ts_malloc(tcpRMax);
        data->tcp.wBufLen = 0;
        data->tcp.wBuf = ts_malloc(tcpWMax);
        data->tcp.window = peerWindow;
        data->tcp.seq = 0;
        data->tcp.ack = htonl(ntohl(*(int *)&buf[iphdrLen + 4]) + 1);
        data->tcp.status = 0x00;
        data->tcp.next = NULL;
        data->tcp.ptr = NULL;

        for (tmp = tcpHead; tmp->tcp.next; tmp = tmp->tcp.next)
            ;
        tmp->tcp.next = data;
        data->tcp.last = tmp;

        /* ack syn */
        handle_tcp_ack(data, 0x00);

        ts_cb(data);

        return;
    }

    /* other tcp data and ack rst */
    int tcphdrLen = 20;
    int bufTmpLen = iphdrLen + tcphdrLen;
    char bufTmp[bufTmpLen];

    if (flag == 4)
    {
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
    }
    else
    {
        struct ip6_hdr *ip6 = (struct ip6_hdr *)&bufTmp[0];
        ip6->ip6_flow = htonl(6 << 28);
        ip6->ip6_plen = htons(20 + bufLen);
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

    if (flag == 4)
    {
        char bufChecksum[12 + bufTmpLen - iphdrLen];
        memcpy(bufChecksum, &buf[16], 4);
        memcpy(&bufChecksum[4], &buf[12], 4);
        *(uint16_t *)&bufChecksum[8] = htons(6);
        *(uint16_t *)&bufChecksum[10] = htons(bufTmpLen - iphdrLen);
        memcpy(&bufChecksum[12], &bufTmp[iphdrLen], bufTmpLen - iphdrLen);
        tcp->check = calculate_checksum((uint16_t *)bufChecksum, 12 + bufTmpLen - iphdrLen);
    }
    else
    {
        char bufChecksum[36 + bufTmpLen - iphdrLen];
        memcpy(bufChecksum, &buf[24], 16);
        memcpy(&bufChecksum[16], &buf[8], 16);
        *(uint16_t *)&bufChecksum[32] = htons(6);
        *(uint16_t *)&bufChecksum[34] = htons(bufTmpLen - iphdrLen);
        memcpy(&bufChecksum[36], &bufTmp[iphdrLen], bufTmpLen - iphdrLen);
        tcp->check = calculate_checksum((uint16_t *)bufChecksum, 36 + bufTmpLen - iphdrLen);
    }

    if (write(tunFd, bufTmp, bufTmpLen))
        ; /* make compile happy */
}

void tcp_write(ts_data_t *data)
{
    if ((data->tcp.wBufLen <= 0) ||
        (data->tcp.window <= 0))
    {
        return;
    }

    int tcphdrLen = 20;
    int iphdrLen = (data->type & 0x0f) ? 20 : 40;
    int bufTmpLen;
    if (data->tcp.window < data->tcp.wBufLen)
    {
        bufTmpLen = iphdrLen + tcphdrLen + data->tcp.window;
    }
    else
    {
        bufTmpLen = iphdrLen + tcphdrLen + data->tcp.wBufLen;
    }
    char bufTmp[bufTmpLen];

    if (data->type & 0x0f)
    {
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
    }
    else
    {
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
    tcp->seq = data->tcp.seq;
    tcp->ack_seq = data->tcp.ack;
    tcp->res1 = 0;
    tcp->doff = 20 / 4;
    ((char *)tcp)[13] = 0x18; /* ack psh */
    if ((tcpRMax - data->tcp.rBufLen) > 65535)
    {
        tcp->window = htons(65535);
    }
    else
    {
        tcp->window = htons(tcpRMax - data->tcp.rBufLen);
    }
    tcp->check = 0;
    tcp->urg_ptr = 0;

    memcpy(&bufTmp[iphdrLen + tcphdrLen], data->tcp.wBuf, bufTmpLen - iphdrLen - tcphdrLen);
    if (data->tcp.window < data->tcp.wBufLen) /* no buffer left, so no need to memmove */
    {
        memmove(data->tcp.wBuf, &data->tcp.wBuf[bufTmpLen - iphdrLen - tcphdrLen], data->tcp.wBufLen - (bufTmpLen - iphdrLen - tcphdrLen));
    }
    data->tcp.wBufLen -= (bufTmpLen - iphdrLen - tcphdrLen);

    if (data->type & 0x0f)
    {
        char bufChecksum[12 + bufTmpLen - iphdrLen];
        memcpy(bufChecksum, data->tcp.dip, 4);
        memcpy(&bufChecksum[4], data->tcp.sip, 4);
        *(uint16_t *)&bufChecksum[8] = htons(6);
        *(uint16_t *)&bufChecksum[10] = htons(bufTmpLen - iphdrLen);
        memcpy(&bufChecksum[12], &bufTmp[iphdrLen], bufTmpLen - iphdrLen);
        tcp->check = calculate_checksum((uint16_t *)bufChecksum, 12 + bufTmpLen - iphdrLen);
    }
    else
    {
        char bufChecksum[36 + bufTmpLen - iphdrLen];
        memcpy(bufChecksum, data->tcp.dip, 16);
        memcpy(&bufChecksum[16], data->tcp.sip, 16);
        *(uint16_t *)&bufChecksum[32] = htons(6);
        *(uint16_t *)&bufChecksum[34] = htons(bufTmpLen - iphdrLen);
        memcpy(&bufChecksum[36], &bufTmp[iphdrLen], bufTmpLen - iphdrLen);
        tcp->check = calculate_checksum((uint16_t *)bufChecksum, 36 + bufTmpLen - iphdrLen);
    }

    if (write(tunFd, bufTmp, bufTmpLen))
        ; /* make compile happy */

    data->tcp.window = 0; /* reset when recv peer ack */
}

void handle_tcp_ack(ts_data_t *data, char flag)
{
    int iphdrLen = (data->type & 0x0f) ? 20 : 40;
    int tcphdrLen = (0x00 == flag) ? 24 : 20;
    int bufTmpLen = iphdrLen + tcphdrLen;
    char bufTmp[bufTmpLen];

    if (data->type & 0x0f)
    {
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
    }
    else
    {
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
    tcp->seq = data->tcp.seq;
    tcp->ack_seq = data->tcp.ack;
    tcp->res1 = 0;
    tcp->doff = tcphdrLen / 4;
    if (flag == 0x00)
    {
        ((char *)tcp)[13] = 0x12; /* ack syn */
    }
    else if (flag == 0x01)
    {
        ((char *)tcp)[13] = 0x10; /* ack */
    }
    else if (flag == 0x02)
    {
        ((char *)tcp)[13] = 0x11; /* ack fin */
    }
    if ((tcpRMax - data->tcp.rBufLen) > 65535)
    {
        tcp->window = htons(65535);
    }
    else
    {
        tcp->window = htons(tcpRMax - data->tcp.rBufLen);
    }
    tcp->check = 0;
    tcp->urg_ptr = 0;

    /* tcp mss */
    if (flag == 0x00)
    {
        if ((tunMtu - iphdrLen - tcphdrLen) > 65535)
        {
            *(int *)&bufTmp[iphdrLen + tcphdrLen - 4] = htonl(0x02040000 + 65535);
        }
        else
        {
            *(int *)&bufTmp[iphdrLen + tcphdrLen - 4] = htonl(0x02040000 + tunMtu - iphdrLen - tcphdrLen);
        }
    }

    if (data->type & 0x0f)
    {
        char bufChecksum[12 + tcphdrLen];
        memcpy(bufChecksum, data->tcp.dip, 4);
        memcpy(&bufChecksum[4], data->tcp.sip, 4);
        *(uint16_t *)&bufChecksum[8] = htons(6);
        *(uint16_t *)&bufChecksum[10] = htons(bufTmpLen - iphdrLen);
        memcpy(&bufChecksum[12], &bufTmp[iphdrLen], tcphdrLen);
        tcp->check = calculate_checksum((uint16_t *)bufChecksum, 12 + tcphdrLen);
    }
    else
    {
        char bufChecksum[36 + tcphdrLen];
        memcpy(bufChecksum, data->tcp.dip, 16);
        memcpy(&bufChecksum[16], data->tcp.sip, 16);
        *(uint16_t *)&bufChecksum[32] = htons(6);
        *(uint16_t *)&bufChecksum[34] = htons(bufTmpLen - iphdrLen);
        memcpy(&bufChecksum[36], &bufTmp[iphdrLen], tcphdrLen);
        tcp->check = calculate_checksum((uint16_t *)bufChecksum, 36 + tcphdrLen);
    }

    if (write(tunFd, bufTmp, bufTmpLen))
        ; /* make compile happy */
}