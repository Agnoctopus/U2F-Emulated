#include <err.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "message.h"
#include "../device/uhid.h"
#include "../utils/xalloc.h"


struct message *message_new(struct packet_init *init_packet)
{
    /* Allocate */
    struct message *message = xmalloc(sizeof(struct message));

    /* Init */
    message->init_packet = init_packet;
    message->cont.begin = NULL;
    message->cont.end = NULL;

    return message;
}

struct message *message_new_blank(uint32_t cid, uint8_t cmd)
{
    /* Init packet */
    struct packet_init *packet = packet_init_new(cid, cmd, 0);

    return message_new(packet);
}

struct message *message_new_from_data(uint32_t cid, uint8_t cmd,
        uint8_t *data, size_t size)
{
    /* Allocate */
    struct message *message = message_new_blank(cid, cmd);

    /* Add data */
    message_add_data(message, data, size);

    if (packet_init_get_bcnt(message->init_packet) != size)
    {
        warnx("Failed to create message from data");
        return NULL;
    }
    return message;
}


void message_add_part(struct message *message,
        struct packet_cont *cont_packet)
{
    /* Allocate */
    struct message_part *message_part =
        xmalloc(sizeof(struct message_part));

    /* Init */
    message_part->packet = cont_packet;
    message_part->next = NULL;

    /* Add */
    if (message->cont.begin == NULL)
    {
        /* Seq */
        cont_packet->seq = 0;

        /* Pointer */
        message->cont.begin = message_part;
        message->cont.end = message->cont.begin;
    }
    else
    {
        /* Seq */
        cont_packet->seq = message->cont.end->packet->seq + 1;

        /* Pointer */
        message->cont.end->next = message_part;
        message->cont.end = message_part;
    }
}

size_t message_data_nb_packets(size_t size)
{
    /* Edge case */
    if (size == 0)
        return 0;

    /* Init packet */
    if (size >= PACKET_INIT_DATA_SIZE)
        size -= PACKET_INIT_DATA_SIZE;
    else
        return 1;

    /* Just on packet */
    if (size == 0)
        return 1;

    /* General case */
    size_t nb = 2;
    while (size > PACKET_CONT_DATA_SIZE)
    {
        size -= PACKET_CONT_DATA_SIZE;

        ++nb;
    }
    return nb;
}

size_t message_nb_packets(const struct message *message)
{
    /* Get message size */
    size_t message_size = packet_init_get_bcnt(message->init_packet);

    /* Get nb_packets */
    size_t nb_packets_data = message_data_nb_packets(message_size);

    size_t nb_packets_message = 1;
    if (message->cont.end != NULL)
        nb_packets_message += 1 + message->cont.end->packet->seq;
    return nb_packets_message;

    /* Blank packet */
    if (nb_packets_data == 0 && nb_packets_message == 1)
        return nb_packets_message;

    /* Check integrity */
    if (nb_packets_data != nb_packets_message)

    {
        warnx("Packet corrupted");
        return 0;
    }
    return nb_packets_data;
}


size_t message_data_max(size_t nb_packets)
{
    if (nb_packets == 0)
        return 0;
    if (nb_packets == 1)
        return PACKET_INIT_DATA_SIZE;
    return PACKET_INIT_DATA_SIZE
        + (nb_packets - 1)
        * PACKET_CONT_DATA_SIZE;
}

static size_t message_last_packet_size(const struct message *message)
{
    /* Get message size */
    size_t message_size = packet_init_get_bcnt(message->init_packet);

    /* Get nb packets */
    size_t nb_packets = message_nb_packets(message);
    if (nb_packets == 0)
        return 0;

    /* Get max message size */
    size_t max_message_size = message_data_max(nb_packets);

    /* Remaine size on last packet */
    size_t remaining_size = max_message_size - message_size;

    /* Are we in first or nth packet */
    if (nb_packets == 1)
        return PACKET_INIT_DATA_SIZE - remaining_size;
    return PACKET_CONT_DATA_SIZE - remaining_size;
}

void message_add_data(struct message *message,
        const uint8_t *data, size_t size)
{
    /* CID */
    uint32_t cid = message->init_packet->cid;

    /* Nb packets */
    size_t nb_packets = message_nb_packets(message);

    /* Remaining size last packet */
    size_t last_packet_size =
        message_last_packet_size(message);

    /* Written */

    /* First packet */
    size_t written = 0;
    if (nb_packets == 1)
    {
        size_t last_packet_remaining =
            PACKET_INIT_DATA_SIZE - last_packet_size;
        size_t towrite = (size <= last_packet_remaining) ? size :
            last_packet_remaining;

        memcpy(message->init_packet->data + last_packet_size,
                data,
                towrite);
        written += towrite;
    }
    else
    {
        size_t last_packet_remaining =
            PACKET_CONT_DATA_SIZE - last_packet_size;
        size_t towrite = (size <= last_packet_remaining) ? size :
            last_packet_remaining;

        memcpy(message->cont.end->packet->data + last_packet_size,
                data,
                towrite);
        written += towrite;
    }
    size -= written;

    /* Intermediate packets */
    while (size >= PACKET_CONT_DATA_SIZE)
    {
        struct packet_cont *packet = packet_cont_new(cid, 0);

        memcpy(packet->data,
                data + written,
                PACKET_CONT_DATA_SIZE);

        written += PACKET_CONT_DATA_SIZE;
        size -= PACKET_CONT_DATA_SIZE;

        message_add_part(message, packet);
    }

    /* Update bcnt */
    packet_init_add_bcnt(message->init_packet, written);

    if (size == 0)
        return;

    /* Last packet */
    struct packet_cont *packet = packet_cont_new(cid, 0);
    memcpy(packet->data,
            data + written,
            size);

    /* Update bcnt */
    packet_init_add_bcnt(message->init_packet, size);
    message_add_part(message, packet);
}

void message_send(int fd, struct message *message)
{
    /* Init packet */
    uhid_device_send_input(fd, message->init_packet, PACKET_SIZE);

    /* Rest of teh packers */
    struct message_part *part = message->cont.begin;
    while (part != NULL)
    {
        /* Send part */
        uhid_device_send_input(fd, part->packet, PACKET_SIZE);

        part = part->next;
    }
}

static const struct message_part *
message_get_nth_message_part(
        const struct message *message, size_t nth)
{
    /* Null case */
    if (message->cont.begin == NULL)
        return NULL;

    /* Loop nth packets */
    const struct message_part *part =
        message->cont.begin;
    for (size_t i = 0; i < nth; ++i)
    {
        part = part->next;
        if (part == NULL)
            return NULL;
    }
    return part;
}

size_t message_read(const struct message *message, uint8_t *buffer,
        size_t offset, size_t size)
{
    /* Compute the number of packets to skip */
    size_t nb_packets = message_data_nb_packets(offset);
    if (nb_packets > 0)
        --nb_packets;

    /* Internal cpt */
    size_t readed = 0;

    /* First packet */
    if (nb_packets == 0)
    {
        /* To read */
        size_t toread = (size < PACKET_INIT_DATA_SIZE - offset) ?
            size : PACKET_INIT_DATA_SIZE - offset;

        memcpy(buffer,
                message->init_packet->data + offset,
                toread);

        readed += toread;
    }
    else
    {
        offset -= message_data_max(nb_packets);

        /* To read */
        size_t toread = (size < PACKET_CONT_DATA_SIZE - offset) ?
            size : PACKET_CONT_DATA_SIZE - offset;

        const struct message_part *part =
            message_get_nth_message_part(
                    message,
                    nb_packets - 1);

        if (part == NULL)
            return 0;

        memcpy(buffer,
                part->packet->data + offset,
                toread);
        readed += toread;
    }
    size -= readed;

    const struct message_part *part =
        message_get_nth_message_part(
                message,
                nb_packets);


    /* Intermediate packets */
    while (size >= PACKET_CONT_DATA_SIZE && part != NULL)
    {

        memcpy(buffer + readed,
                part->packet->data,
                PACKET_CONT_DATA_SIZE);

        readed += PACKET_CONT_DATA_SIZE;
        size -= PACKET_CONT_DATA_SIZE;

        part = part->next;
    }

    if (size == 0 || part == NULL)
        return readed;

    memcpy(buffer + readed,
            part->packet->data,
            size);
    return readed + size;
}

void message_free(struct message *message)
{
    /* Cont packets */
    struct message_part *part = message->cont.begin;
    while (part != NULL)
    {
        /* Tmp */
        struct message_part *tmp = part->next;

        /* Part */
        free(part->packet);
        free(part);

        part = tmp;
    }

    /* Init packet */
    free(message->init_packet);

    /* Message */
    free(message);
}
