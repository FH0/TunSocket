#include "misc.h"

inline void *ts_malloc(int len) {
    void *ptr = calloc(len, 1);
    ASSERT(ptr != NULL);
    return (void *)ptr;
}

/* copy form internet :) */
uint16_t calculate_checksum(uint16_t *buf, int len) {
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
