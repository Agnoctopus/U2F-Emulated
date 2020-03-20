#ifndef FRAME_H
#define FRAME_H

#include <stdint.h>

/* Packed macro */
#define __packed __attribute__((__packed__))

struct frame_header
{
    uint8_t cla;
    uint8_t ins;
    uint8_t p1;
    uint8_t p2;
    uint8_t optional[4];
} __packed;

#endif
