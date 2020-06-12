#include <err.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include "commands.h"

#include "../u2f-raw/raw_message.h"


const char *error_msg(int error_nb)
{
    switch (error_nb)
    {
        case ERROR_INVALID_CMD:
            return "Invalid command";
        case ERROR_INVALID_PAR:
            return "Invalid parameter";
        case ERROR_INVALID_LEN:
            return "Invalid message length";
        case ERROR_INVALID_SEQ:
            return "Invalid message sequence";
        case ERROR_MSG_TIMEOUT:
            return "Invalid timed out";
        case ERROR_CHANNEL_BUSY:
            return "Channel busy";
        case ERROR_CMD_LOCK_RQR:
            return "Command require channel lock";
        case ERROR_SYNC_FAILED:
            return "Command sync failed";
        default:
            return "Unknow command";
    }
    /* Should never be executed */

    return NULL;
}

struct message *cmd_generate_error(uint32_t cid, uint8_t error)
{
    /* Init the packet */
    struct packet_init *packet = packet_init_new(cid, CMD_ERROR, 1);

    /* Fill it */
    packet->data[0] = error;

    /* Encapastule it */
    return message_new(packet);
}

/**
** \brief The command handler
*/
typedef
struct message *(*cmd_handler)(const struct message *request);

/**
** \brief The Handler for CMD_INIT
**
** \param request The request
** \return The response
*/
static struct message *cmd_init_handler(
        const struct message *request)
{
    /* Log */
    fprintf(stderr, "   Init\n");

    /* Check message size*/
    if (packet_init_get_bcnt(request->init_packet)
            != U2FHID_INIT_BCNT)
        return NULL;

    struct packet_init *packet = packet_init_new(BROADCAST_CHANNEL,
            CMD_INIT, 17);

    /* Get payload */
    struct cmd_init_response_payload *payload =
        (struct cmd_init_response_payload *)packet->data;

    /* Fill payload */
    memcpy(payload->nonce, request->init_packet->data,
        U2FHID_INIT_BCNT);
    payload->cid = 2;
    payload->protocol_ver = PROTOCOL_VERSION;
    payload->maj_dev_ver = MAJ_DEV_VERSION;
    payload->min_dev_ver = MIN_DEV_VERSION;
    payload->build_dev_ver = BUILD_DEV_VERSION;
    payload->cap_flags = CAP_FLAGS;

    /* Encapsule it */
    struct message *response = message_new(packet);

    return response;
}

/**
** \brief The Handler for CMD_PING
**
** \param request The request
** \return The response
*/
static struct message *cmd_ping_handler(
    const struct message *request)
{
    /* Log */
    fprintf(stderr, "   Ping\n");
    (void) request;
    return NULL;
}

/**
** \brief The Handler for CMD_MSG
**
** \param request The request
** \return The response
*/
static struct message *cmd_msg_handler(
    const struct message *request)
{
    /* Log */
    fprintf(stderr, "   Msg\n");
    return raw_msg_handler(request);
}

/**
** \brief The Handler for CMD_LOCK
**
** \param request The request
** \return The response
*/
static struct message *cmd_lock_handler(
    const struct message *request)
{
    /* Log */
    fprintf(stderr, "   Lock\n");
    (void) request;
    return NULL;
}

/**
** \brief The Handler for CMD_WINK
**
** \param request The request
** \return The response
*/
static struct message *cmd_wink_handler(
    const struct message *request)
{
    /* Log */
    fprintf(stderr, "   Wink\n");
    (void) request;
    return NULL;
}

/**
** \brief The Handler for CMD_SYNC
**
** \param request The request
** \return The response
*/
static struct message *cmd_sync_handler(
    const struct message *request)
{
    /* Log */
    fprintf(stderr, "   Sync\n");
    (void) request;
    return NULL;
}

/**
** \brief The Handler for CMD_ERROR
**
** \param request The request
** \return The response
*/
static struct message *cmd_error_handler(
    const struct message *request)
{
    /* Log */
    fprintf(stderr, "   Error\n");
    (void) request;
    return NULL;
}


/**
** \brief Get the command handler for a specific command
**
** \param cmd The command
** \return The command handler
*/
static cmd_handler cmd_get_handler(uint8_t cmd)
{
    struct cmd_entry
    {
        uint8_t cmd;
        cmd_handler handler;
    };
    static const struct cmd_entry cmd_entries[] =
    {
        {CMD_PING,  cmd_ping_handler    },
        {CMD_MSG,   cmd_msg_handler     },
        {CMD_LOCK,  cmd_lock_handler    },
        {CMD_INIT,  cmd_init_handler    },
        {CMD_WINK,  cmd_wink_handler    },
        {CMD_SYNC,  cmd_sync_handler    },
        {CMD_ERROR, cmd_error_handler   }
    };
    static const size_t cmd_entries_length =
        sizeof(cmd_entries) / sizeof(struct cmd_entry);

    /* Loop though command entries */
    for (size_t i = 0; i < cmd_entries_length; ++i)
    {
        if (cmd == cmd_entries[i].cmd)
            return cmd_entries[i].handler;
    }

    warnx("Packet Handler: Unknown packet command: %d", cmd);

    return NULL;
}

struct message *cmd_process(const struct message *request)
{
    /* Get the handler */
    cmd_handler handler = cmd_get_handler(request->init_packet->cmd);

    /* Dump response */
    size_t request_buffer_size =
        packet_init_get_bcnt(request->init_packet);
    uint8_t *request_buffer = malloc(request_buffer_size);
    message_read(request, request_buffer, 0, request_buffer_size);
    dump_bytes("Message IN:", request_buffer, request_buffer_size);


    /* Check */
    if (handler == NULL)
        return cmd_generate_error(request->init_packet->cid,
                ERROR_INVALID_CMD);

    /* Handle it */
    struct message *response = handler(request);

    return response;
}
