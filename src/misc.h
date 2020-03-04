#ifndef MISC_H__VFH5Y
#define MISC_H__VFH5Y

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
#define ELOG(ptr)                                                              \
    do {                                                                       \
        if (!(ptr)) {                                                          \
            perror("");                                                        \
        }                                                                      \
    } while (0)

uint16_t calculate_checksum(uint16_t *ptr, int ptrLen);
void hex_dump(char *ptr, int ptrLen);
int ts_timeout_read(int fd, char *buf, int bufSize, int timeout);
long long get_usec();
int ring_copy_out(char *ringBuf, int ringSize, int p, int len, char *buf,
                  int bufLen);
int ring_input(char *ringBuf, int ringSize, int p, int *len, char *buf,
               int bufLen);

#endif /* MISC_H__VFH5Y */