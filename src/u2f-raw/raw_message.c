#include <err.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include "frame.h"
#include "raw_message.h"
#include "register.h"
#include "authenticate.h"

#include "../u2f-hid/commands.h"
#include "../crypto.h"
#include "../utils/xalloc.h"

struct key_handle
{
    uint8_t key[32];
    uint8_t app_param[32];
};

/**
** The command handler
*/
typedef struct message *(*raw_handler)(const struct message *message);


struct message *raw_version_handler(const struct message *message)
{
    fprintf(stderr, "       version\n");
    (void) message;

    struct packet_init *packet = packet_init_new(
            message->init_packet->cid, CMD_MSG,
            strlen(VERSION_STR) + 2);

    /* Fill payload */
    memcpy(packet->data, VERSION_STR, strlen(VERSION_STR));
    packet->data[strlen(VERSION_STR)] = SW_NO_ERROR >> 8;
    packet->data[strlen(VERSION_STR) + 1] = SW_NO_ERROR & 0xFF;

    /* Encapsule it */
    struct message *response = message_new(packet);

    return response;
}

raw_handler raw_msg_get_handler(uint8_t cmd)
{
    struct cmd_entry
    {
        uint8_t cmd;
        raw_handler handler;
    };
    static const struct cmd_entry cmd_entries[] =
    {
        {   U2F_REGISTER,     raw_register_handler        },
        {   U2F_AUTHENTICATE, raw_authenticate_handler    },
        {   U2F_VERSION,      raw_version_handler         },
    };
    static const size_t cmd_entries_length =
        sizeof(cmd_entries) / sizeof(struct cmd_entry);

    /* Loop though command entries */
    for (size_t i = 0; i < cmd_entries_length; ++i)
    {
        if (cmd == cmd_entries[i].cmd)
            return cmd_entries[i].handler;
    }

    warnx("Packet Handler: Unknown raw command: %d", cmd);

    return NULL;
}

struct message *raw_msg_handler(const struct message *message)
{
    /* Get frame header */
    struct frame_header *header = (struct frame_header*)
        message->init_packet->data;

    /* Get raw handler */
    raw_handler handler = raw_msg_get_handler(header->ins);
    if (handler == NULL)
        return NULL;

    return handler(message);
}
