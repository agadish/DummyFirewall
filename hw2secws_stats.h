#ifndef __HW2SECWS_STATS_H__
#define __HW2SECWS_STATS_H__

#include <stdint.h>

#pragma pack(1)
typedef struct hw2secws_stats_s {
    uint32_t accepted_packets;
    uint32_t dropped_packets;
} hw2secws_stats_t;

#endif /* __HW2SECWS_STATS_H__ */
