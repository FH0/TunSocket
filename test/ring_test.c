#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int ring_input(char *ringBuf, int ringSize, int p, int *len, char *buf,
               int bufLen) {
    if ((*len >= ringSize) || (bufLen <= 0)) {
        errno = EAGAIN;
        return -1;
    }
    int ringLeft = ringSize - *len;
    int inLen = (ringLeft < bufLen) ? ringLeft : bufLen;
    if ((p + *len + inLen) <= ringSize) {
        memcpy(&ringBuf[p], buf, inLen);
    } else {
        int nleft = p + inLen - ringSize;
        int nright = inLen - nleft;
        memcpy(&ringBuf[p], buf, nright);
        memcpy(ringBuf, &buf[nright], nleft);
    }
    *len += inLen;
    errno = 0;
    return inLen;
}

int ring_copy_out(char *ringBuf, int ringSize, int p, int len, char *buf,
                  int bufLen) {
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

int main(int argc, char const *argv[]) {
    FILE *in = fopen("100M", "rb");
    FILE *out = fopen("100M.bak", "wb");
    int p = 0;
    int tmp1Len = 0;
    char tmp1[192 * 1024];
    char tmp2[1460];

    for (;;) {
        int nread = fread(tmp2, 1, 1460, in);
        ring_input(tmp1, 192 * 1024, p, &tmp1Len, tmp2, nread);
        int ncopy = ring_copy_out(tmp1, 192 * 1024, p, tmp1Len, tmp2, 1460);
        tmp1Len -= ncopy;
        p = (p + ncopy) % (192 * 1024);
        printf("p %d\n", p);
        fwrite(tmp2, 1, ncopy, out);
        if (nread < 1460)
            break;
    }

    fclose(in);
    fclose(out);
    return 0;
}
