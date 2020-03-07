#ifndef API_H__VFH5Y
#define API_H__VFH5Y

#include <tunsocket.h>

extern uint32_t tcpRMax;
extern uint32_t tcpWMax;
extern ts_data_t *tcpHead;
extern int tunFd;
extern uint32_t tunMtu;

extern void (*ts_cb)(ts_data_t *data);

#endif /* API_H__VFH5Y */