#ifndef API_H__VFH5Y
#define API_H__VFH5Y

#include <tunsocket.h>

extern int tcpRMax;
extern int tcpWMax;
extern ts_data_t *tcpHead;
extern int tunFd;
extern int tunMtu;
extern int tcpET;

extern void (*ts_cb)(ts_data_t *data);

#endif /* API_H__VFH5Y */