#ifndef COMMANDS_H
#define COMMANDS_H

#include <stdint.h>

#include "message.h"


/* bit macro */
#define BIT(x) (1 << (x))

/* Packed macro */
#define __packed __attribute__((__packed__))

/* Command bits */
#define CMD_PING    BIT(7) | 0x1
#define CMD_MSG     BIT(7) | 0x3
#define CMD_LOCK    BIT(7) | 0x4
#define CMD_INIT    BIT(7) | 0x6
#define CMD_WINK    BIT(7) | 0x8
#define CMD_SYNC    BIT(7) | 0x3c
#define CMD_ERROR   BIT(7) | 0x3f

/* Errors bits */
#define ERROR_INVALID_CMD   1
#define ERROR_INVALID_PAR   2
#define ERROR_INVALID_LEN   3
#define ERROR_INVALID_SEQ   4
#define ERROR_MSG_TIMEOUT   5
#define ERROR_CHANNEL_BUSY  6
#define ERROR_CMD_LOCK_RQR  7
#define ERROR_SYNC_FAILED   8


struct cmd_init_payload_in
{
    uint8_t nonce[8]; /**< Nonce */
} __packed;

struct cmd_init_payload_out
{
    uint8_t nonce[8]; /**< Nonce */
    uint32_t cid; /**< Channel id */
    uint8_t protocol_ver; /**< U2FHID protocol version */
    uint8_t maj_dev_ver; /**< Major device version */
    uint8_t min_dev_ver; /**< Minor device version */
    uint8_t build_dev_ver; /**< Build device version */
    uint8_t cap_flags; /**< Capabilities flags */
} __packed;


/**
** \brief Get the respective error description
**
** \param error_nb The error number
** \return The respective error description
*/
const char *error_msg(int error_nb);

struct message *cmd_generate_error(uint32_t cid, uint8_t error);

struct message *cmd_process(const struct message *message);

#endif
