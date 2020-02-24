#include "misc.h"

/* copy form internet :) */
uint16_t calculate_checksum(uint16_t *ptr, int ptrLen) {
    int sum = 0;
    while (ptrLen > 1) {
        sum += *ptr++;
        ptrLen -= 2;
    }
    if (ptrLen == 1) {
        char tmp[2];
        tmp[0] = *(char *)ptr;
        tmp[1] = 0;
        sum += *(char *)tmp;
    }
    while (sum >> 16) {
        sum = (sum >> 16) + (sum & 0xffff);
    }

    return (uint16_t)~sum;
}
