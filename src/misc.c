#include "misc.h"

inline uint64_t get_usec() {
    struct timeval time;
    gettimeofday(&time, NULL);
    return time.tv_sec * 1000 * 1000 + time.tv_usec;
}

int ring_input(char *ringBuf, uint32_t ringSize, uint32_t p, uint32_t *len,
               char *buf, int bufLen) {
    if (*len >= ringSize || bufLen <= 0) {
        errno = EAGAIN;
        return -1;
    }
    int ringLeft = ringSize - *len;
    int inLen = (ringLeft < bufLen) ? ringLeft : bufLen;
    uint32_t pEnd = (p + *len) % ringSize;
    if ((pEnd + inLen) <= ringSize) {
        memcpy(&ringBuf[pEnd], buf, inLen);
    } else {
        int nleft = pEnd + inLen - ringSize;
        int nright = inLen - nleft;
        memcpy(&ringBuf[pEnd], buf, nright);
        memcpy(ringBuf, &buf[nright], nleft);
    }
    *len += inLen;
    errno = 0;
    return inLen;
}

int ring_copy_out(char *ringBuf, uint32_t ringSize, uint32_t p, uint32_t len,
                  char *buf, int bufLen) {
    if ((len <= 0) || (bufLen <= 0)) {
        errno = EAGAIN;
        return -1;
    }
    int outLen = (len < bufLen) ? len : bufLen;
    if ((p + outLen) <= ringSize) {
        memcpy(buf, &ringBuf[p], outLen);
    } else {
        int nleft = p + outLen - ringSize;
        int nright = outLen - nleft;
        memcpy(buf, &ringBuf[p], nright);
        memcpy(&buf[nright], ringBuf, nleft);
    }
    errno = 0;
    return outLen;
}

void *ts_malloc(int len) {
    // void *ptr = calloc(len, 1);
    void *ptr = malloc(len);
    ASSERT(ptr != NULL);
    return (void *)ptr;
}

/* copy form internet :) */
inline uint16_t calculate_checksum(uint16_t *buf, int len) {
    long sum = 0;

    while (len > 1) {
        sum += *buf++;
        if (sum & 0x80000000)
            sum = (sum & 0xFFFF) + (sum >> 16);
        len -= 2;
    }

    if (len)
        sum += (uint16_t) * (uint8_t *)buf;

    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);

    return ~sum;
}

inline void hex_dump(char *ptr, int ptrLen) {
    int i;
    for (i = 0; i < ptrLen; i++) {
        printf(" %02X", ptr[i]);
        if (((i + 1) % 16) == 0) {
            printf("\n");
        } else if (((i + 1) % 8) == 0) {
            printf(" ");
        }
    }
    if (((i + 1) % 16) != 0) {
        printf("\n");
    }
    printf("\n\n");
}

inline void save_to_file(char *file, char *buf, int bufLen) {
    FILE *f = fopen(file, "ab");
    fwrite(buf, 1, bufLen, f);
    fclose(f);
}
