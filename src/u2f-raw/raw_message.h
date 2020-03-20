#ifndef RAW_MESSAGE_H
#define RAW_MESSAGE_H

#include <stdint.h>

#include "../u2f-hid/message.h"


/* Packed macro */
#define __packed __attribute__((__packed__))

/* Commands bits */
#define U2F_REGISTER 0x01
#define U2F_AUTHENTICATE 0x02
#define U2F_VERSION 0x03

/* Status code */
#define SW_NO_ERROR 0x9000
#define SW_CONDITIONS_NOT_SATISFIED 0x6985
#define SW_WRONG_DATA 0x6A80
#define SW_WRONG_LENGTH 0x6700
#define SW_CLA_NOT_SUPPORTED 0x6E00
#define SW_INS_NOT_SUPPORTED 0x6D00

#define VERSION_STR "U2F_V2"

/* Authenticate bits */
#define U2F_AUTH_CHECK 0x07
#define U2F_AUTH_ENFORCE 0x03
#define U2F_AUTH_NO_ENFORCE 0x08

struct registration_request
{
    uint8_t challenge_param[32]; /**< SHA-256 client data */
    uint8_t application_param[32]; /**< SHA-256 App Id */
} __packed;

struct authentification_request
{
    uint8_t challenge_param[32]; /**< SHA-256 client data */
    uint8_t application_param[32]; /**< SHA-256 App Id */
    uint8_t key_handle_size;
    uint8_t key_handle[];
} __packed;


struct message *raw_msg_handler(const struct message *message);

#include <stdio.h>
static inline void dump_bytes(const char *str,
    const uint8_t *data, size_t size)
{
    puts("----------------------------");
    printf("%s: %zu:\n", str, size);

    size_t i = 0;
    for (i = 0; i < size; ++i)
    {
        printf("%02x ", data[i]);
        if ((i + 1) % 16 == 0)
            puts("");
    }
    if ((i + 1) % 16 != 0)
        puts("");
    puts("----------------------------");

}

#endif
