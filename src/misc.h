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

uint16_t calculate_checksum(uint16_t *ptr, int ptrLen);

#endif /* MISC_H__VFH5Y */