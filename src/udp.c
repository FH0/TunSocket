#include "udp.h"
#include "event.h"
#include "misc.h"

void ts_udp_write(char flag, void *sip, uint16_t sport, void *dip,
                  uint16_t dport, void *buf, int bufLen) {
    int iphdrLen = (flag == TS_UDP) ? 20 : 40;
    int udphdrLen = 8;
    int bufTmpLen = iphdrLen + udphdrLen + bufLen;
    char bufTmp[bufTmpLen];

    if (flag == TS_UDP) {
        struct iphdr *ip = (struct iphdr *)&bufTmp[0];
        ip->version = 4;
        ip->ihl = 5;
        ip->tos = 0;
        ip->tot_len = htons(bufTmpLen);
        ip->id = 0;
        ip->frag_off = 0;
        ip->ttl = 64;
        ip->protocol = 17;
        ip->check = 0;
        memcpy(&ip->saddr, sip, 4);
        memcpy(&ip->daddr, dip, 4);
        ip->check = calculate_checksum((uint16_t *)ip, 20);
    } else {
        struct ip6_hdr *ip6 = (struct ip6_hdr *)&bufTmp[0];
        ip6->ip6_flow = htonl(6 << 28);
        ip6->ip6_plen = htons(8 + bufLen);
        ip6->ip6_nxt = 17;
        ip6->ip6_hlim = 64;
        memcpy(&ip6->ip6_src, sip, 16);
        memcpy(&ip6->ip6_dst, dip, 16);
    }

    struct udphdr *udp = (struct udphdr *)&bufTmp[iphdrLen];
    udp->source = sport;
    udp->dest = dport;
    udp->len = htons(udphdrLen + bufLen);
    udp->check = 0;

    memcpy(&bufTmp[iphdrLen + udphdrLen], buf, bufLen);

    /* udp checksum is optional */
    if (flag == TS_UDP) {
        char bufChecksum[12 + bufTmpLen - iphdrLen];
        memcpy(bufChecksum, dip, 4);
        memcpy(&bufChecksum[4], sip, 4);
        *(uint16_t *)&bufChecksum[8] = htons(17);
        *(uint16_t *)&bufChecksum[10] = htons(bufTmpLen - iphdrLen);
        memcpy(&bufChecksum[12], &bufTmp[iphdrLen], bufTmpLen - iphdrLen);
        udp->check = calculate_checksum((uint16_t *)bufChecksum,
                                        12 + bufTmpLen - iphdrLen);
    } else {
        char bufChecksum[36 + bufTmpLen - iphdrLen];
        memcpy(bufChecksum, dip, 16);
        memcpy(&bufChecksum[16], sip, 16);
        *(uint16_t *)&bufChecksum[32] = htons(17);
        *(uint16_t *)&bufChecksum[34] = htons(bufTmpLen - iphdrLen);
        memcpy(&bufChecksum[36], &bufTmp[iphdrLen], bufTmpLen - iphdrLen);
        udp->check = calculate_checksum((uint16_t *)bufChecksum,
                                        36 + bufTmpLen - iphdrLen);
    }

    if (write(tunFd, bufTmp, bufTmpLen))
        ; /* make compile happy */
}

void handle_udp(char flag, ts_data_t *data, char *buf, int bufLen) {
    int iphdrLen = (flag == TS_UDP) ? (buf[0] & 0x0f) * 4 : 40;
    int udphdrLen = 8;

    data->type = flag;
    if (flag == TS_UDP) {
        memcpy(data->udp.sip, &buf[12], 4);
        memcpy(data->udp.dip, &buf[16], 4);
    } else {
        memcpy(data->udp.sip, &buf[8], 16);
        memcpy(data->udp.dip, &buf[24], 16);
    }
    data->udp.sport = *(uint16_t *)&buf[iphdrLen];
    data->udp.dport = *(uint16_t *)&buf[iphdrLen + 2];
    data->udp.bufLen = bufLen - iphdrLen - udphdrLen;
    data->udp.buf = &buf[iphdrLen + udphdrLen];
}
