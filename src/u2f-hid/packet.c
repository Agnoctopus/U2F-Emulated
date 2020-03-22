#include <err.h>
#include <string.h>

#include "commands.h"
#include "packet.h"
#include "transaction.h"
#include "../utils/xalloc.h"


struct packet_init *packet_init_new(uint32_t cid, uint8_t cmd,
        uint16_t bcnt)
{
    /* Allocate */
    struct packet_init *packet = xcalloc(1, sizeof(struct packet_init));

    /* Init */
    packet->cid = cid;
    packet->cmd = cmd;
    packet_init_set_bcnt(packet, bcnt);

    return packet;

}

struct packet_cont *packet_cont_new(uint32_t cid, uint8_t seq)
{
    /* Allocate */
    struct packet_cont *packet = xcalloc(1, sizeof(struct packet_cont));

    /* Init */
    packet->cid = cid;
    packet->seq = seq;

    return packet;
}

static struct message *packet_init_handle(
        const struct packet_init *packet)
{
    /* Encapsule */
    struct message *request = message_new(packet_copy(packet));

    if (packet_init_get_bcnt(request->init_packet)
            <= PACKET_INIT_DATA_SIZE)
    {
        /* Reponse */
        struct message *response = cmd_process(request);

        /* Free */
        message_free(request);

        return response;
    }
    /* Transaction */
    transaction_start(request);

    return NULL;
}

static struct message *packet_cont_handle(
        const struct packet_cont *packet)
{
    /* Get the transaction request */
    struct message *request = transaction_request();

    /* Add cont packet */
    message_add_part(request, packet_copy(packet));

    size_t nb_packet = message_nb_packets(request);
    size_t nb_packet_wanted =
        message_data_nb_packets(
                packet_init_get_bcnt(request->init_packet));
    if (nb_packet == nb_packet_wanted)
    {
        /* Process */
        struct message *response = cmd_process(request);

        /* End transaction */
        transaction_stop();

        /* Free */
        message_free(request);

        return response;
    }

    return NULL;
}

void *packet_copy(const void *packet)
{
    /* Allocate */
    void *packet_cpy = xmalloc(PACKET_SIZE);

    /* Copy */
    memcpy(packet_cpy, packet, PACKET_SIZE);

    return packet_cpy;
}

struct message *packet_handle(const void *packet, size_t size)
{
    /* Get the cid */
    uint32_t cid = packet_get_cid(packet);

    /* Check packet size */
    if (size != PACKET_SIZE)
    {
        warn("Wrong packet size: %zu != %d (Expected)",
                size, PACKET_SIZE);
        return cmd_generate_error(cid, ERROR_INVALID_CMD);
    }

    /* Gte the packet_type */
    bool init_packet = packet_is_init(packet);

    if (init_packet)
    {
        if (!transaction_on_going())
            return packet_init_handle(packet);
        else
            return cmd_generate_error(cid, ERROR_CHANNEL_BUSY);
    }
    else
    {
        if (transaction_cid_in(cid))
            return packet_cont_handle(packet);
        else
            return cmd_generate_error(cid, ERROR_CHANNEL_BUSY);

    }
    /* Should not happend */

    return NULL;
}
