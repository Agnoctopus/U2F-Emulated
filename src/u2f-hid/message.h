#ifndef MESSAGE_H
#define MESSAGE_H

#include <stdint.h>

#include "packet.h"


/* Packed macro */
#define __packed __attribute__((__packed__))

/* BIT macro */
#define BIT(x) (1 << (x))



#define U2FHID_INIT_BCNT 8

#define PROTOCOL_VERSION 2
#define MAJ_DEV_VERSION 0
#define MIN_DEV_VERSION 1
#define BUILD_DEV_VERSION 0
#define CAP_FLAGS 0

#define CAPABILITY_WINK 0

/**
** \brief Represent a message part
*/
struct message_part
{
    struct packet_cont *packet; /**< The packet of the part */
    struct message_part *next; /**<  The next part */
};

/**
** \brief Represent a message, composed of packets
*/
struct message
{
    struct packet_init *init_packet; /**< The init packet  */
    struct
    {
        struct message_part *begin; /**< The first cont packet */
        struct message_part *end; /**< The last cont packet */
    } cont; /**< The cont packets */
};

/**
** \brief Allocate and initialize a new message
**
** \parma init_packet The initialisation packet of the message
** \return The new allocated and initialiazed packet
*/
struct message *message_new(struct packet_init *init_packet);

struct message *message_new_blank(uint32_t cid, uint8_t cmd);

struct message *message_new_from_data(uint32_t cid, uint8_t cmd,
        uint8_t *data, size_t size);


/**
** \brief Get the number of packets needed from the given size bytes
**
** \param size the size in bytes
** \return The number of packets needed
*/
size_t message_data_nb_packets(size_t size);

/**
** \brief Get the number of packets in a message
**
** \param message The message
** \return The number of packets
*/
size_t message_nb_packets(const struct message *message);

/**
** \brief Compute the meximum payload that n packets can contains
**
** \param nb_packets The mumber of packets
** \return The maximum payload
*/
size_t message_data_max(size_t nb_packets);

/**
** \brief Add a part to a message
**
** \param message The message
** \param cont_paclet The continuation packet
*/
void message_add_part(struct message *message,
        struct packet_cont *cont_packet);

/**
** \brief Add data to a message
**
** \param message The message
** \param data The data
** \param size The size
*/
void message_add_data(struct message *message,
        const uint8_t *data, size_t size);

size_t message_read(const struct message *message, uint8_t *buffer,
        size_t offset, size_t size);

/**
** \brief Send the message to the kernel
**
** \param fd The fd of the device
** \param message The message
*/
void message_send(int fd, struct message *message);


/**
** \brief Free a message
**
** \param message The message
*/
void message_free(struct message *message);

#endif
