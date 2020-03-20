#ifndef PACKET_H
#define PACKET_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>


/* Packed macroyy */
#define __packed __attribute__((__packed__))

/* Packet general size */
#define PACKET_SIZE 64

/* Init packet speceif sizes */
#define PACKET_INIT_HEADER_SIZE 7
#define PACKET_INIT_DATA_SIZE (PACKET_SIZE - PACKET_INIT_HEADER_SIZE)

/* Cont packet speceif sizes */
#define PACKET_CONT_HEADER_SIZE 5
#define PACKET_CONT_DATA_SIZE (PACKET_SIZE - PACKET_CONT_HEADER_SIZE)

/* Broadcast channels */
#define BROADCAST_CHANNEL 0xFFFFFFFF

/**
** \brief U2FHID packet use for start messsaging during transaction
*/
struct packet_init
{
    uint32_t cid; /**< Channel identifier */
    uint8_t cmd; /**< Command identifier (bit 7 always set) */
    uint8_t bcnth; /**< High part of payload length */
    uint8_t bcntl; /**< Low part of the payload length */
    uint8_t data[PACKET_INIT_DATA_SIZE]; /**< Payload data */
} __packed;

/**
** \brief U2FHID packet use for start messsaging during transaction
*/
struct packet_cont
{
    uint32_t cid; /**< Channel identifier */
    uint8_t seq; /**< Packet sequence 0x00..0x7f (bit 7 always cleared)*/
    uint8_t data[PACKET_CONT_DATA_SIZE]; /**< Payload data */
} __packed;

static inline uint32_t packet_get_cid(const void *packet)
{
    return *((uint32_t *)packet);
}

static inline bool packet_is_init(const void *packet)
{
    return ((uint8_t *)packet)[4] & (1 << 7);
}

static inline uint16_t packet_init_get_bcnt(
        const struct packet_init *init_packet)
{
    uint16_t bcnt = 0;
    bcnt |= init_packet->bcnth << 8;
    bcnt |= init_packet->bcntl;

    return bcnt;
}

static inline void packet_init_set_bcnt(
        struct packet_init *init_packet, uint16_t bcnt)
{
    /* High */
    init_packet->bcnth = bcnt >> 8;

    /* Low */
    init_packet->bcntl = bcnt & 0xFF;
}

static inline void packet_init_add_bcnt(
        struct packet_init *init_packet, uint16_t value)
{
    /* Current bcnt */
    uint16_t bcnt = packet_init_get_bcnt(init_packet);

    /* Update */
    packet_init_set_bcnt(init_packet, bcnt + value);
}

struct message *packet_handle(const void *packet, size_t size);

/**
** \brief Allocate and initialize a initialisation packet
**
** \param cmd The commannd
** \param bcnt The payload length
** \return The initialisation packet allocated and initialized
*/
struct packet_init *packet_init_new(uint32_t cid, uint8_t cmd,
        uint16_t bcnt);

/**
** \brief Allocate and initialize a initialisation packet
**
** \param cmd The commannd
** \param seq The packet sequence
** \return The continuation packet allocated and initialized
*/
struct packet_cont *packet_cont_new(uint32_t cid, uint8_t seq);

/**
** \brief Copy a packet
**
** \param The packet to copy
** \return The copy
*/
void *packet_copy(const void *packet);

#endif
