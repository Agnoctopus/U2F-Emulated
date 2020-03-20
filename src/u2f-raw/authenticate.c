#include <err.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include "frame.h"
#include "raw_message.h"
#include "authenticate.h"
#include "register.h"

#include "../u2f-hid/commands.h"
#include "../u2f-hid/packet.h"
#include "../u2f-hid/message.h"

#include "../crypto.h"
#include "../utils/xalloc.h"
#include "authenticate.h"


static bool buffereq(const uint8_t *buffer1,
    const uint8_t *buffer2, size_t size)
{
    for (size_t i = 0; i < size; ++i)
    {
        if (buffer1[i] != buffer2[i])
            return false;
    }
    return true;
}

struct message *raw_authenticate_check(const struct message *message)
{
    fprintf(stderr, "           check\n");

    /* Request */
    struct authentification_request request;
    message_read(message,
        (uint8_t *)&request,
        7,
        sizeof(struct authentification_request));

    /* Response */
    struct message *response =
        message_new_blank(message->init_packet->cid, CMD_MSG);

    /* Key handle ciphered */
    uint8_t *key_handle_cipher = xmalloc(request.key_handle_size);
    message_read(message, key_handle_cipher,
                 65 + 7, request.key_handle_size);
    dump_bytes("key_handle_cipher", key_handle_cipher, request.key_handle_size);

    /* Key handle */
    uint8_t *key_handle = NULL;
    size_t key_handle_size =
        crypto_aes_decrypt(key_handle_cipher,
                           request.key_handle_size,
                           &key_handle);
    dump_bytes("key_handle", key_handle, key_handle_size);
    free(key_handle_cipher);

    /* Privkey */
    size_t privkey_size = key_handle_size - 32;
    dump_bytes("App", key_handle + privkey_size, 32);
    dump_bytes("App2", request.application_param, 32);

    if (!buffereq(key_handle + privkey_size,
        request.application_param, 32))
    {
        warnx("Nope");

        /* SW */
        uint8_t sw[2] = {SW_WRONG_DATA >> 8,
                        SW_WRONG_DATA & 0xFF};
        message_add_data(response, sw, 2);
        dump_bytes("SW", sw, 2);
    }
    else
    {
        /* SW */
        uint8_t sw[2] = {SW_CONDITIONS_NOT_SATISFIED >> 8,
                        SW_CONDITIONS_NOT_SATISFIED & 0xFF};
        message_add_data(response, sw, 2);
        dump_bytes("SW", sw, 2);
    }

    /* Dump request */
    size_t buffer_dump_size = packet_init_get_bcnt(message->init_packet);
    uint8_t *buffer_dump = xmalloc(buffer_dump_size);
    message_read(message, buffer_dump, 0, buffer_dump_size);
    dump_bytes("Request", buffer_dump, buffer_dump_size);
    free(buffer_dump);

    /* Dump response */
    buffer_dump_size = packet_init_get_bcnt(response->init_packet);
    buffer_dump = xmalloc(buffer_dump_size);
    message_read(response, buffer_dump, 0, buffer_dump_size);
    dump_bytes("Response", buffer_dump, buffer_dump_size);
    free(buffer_dump);


    return response;
}

struct message *raw_authenticate_enforce(const struct message *message)
{
    fprintf(stderr, "           enforce\n");

    /* Request */
    struct authentification_request request;
    message_read(message, (uint8_t *)&request,
                 7, sizeof(struct authentification_request));

    /* Response */
    struct message *response =
        message_new_blank(message->init_packet->cid, CMD_MSG);

    /* Key handle ciphered */
    uint8_t *key_handle_cipher = xmalloc(request.key_handle_size);
    message_read(message, key_handle_cipher,
                 65 + 7, request.key_handle_size);
    dump_bytes("key_handle_cipher", key_handle_cipher, request.key_handle_size);

    /* Key handle */
    uint8_t *key_handle = NULL;
    size_t key_handle_size =
        crypto_aes_decrypt(key_handle_cipher,
                           request.key_handle_size,
                           &key_handle);
    dump_bytes("key_handle", key_handle, key_handle_size);
    free(key_handle_cipher);

    /* Privkey */
    size_t privkey_size = key_handle_size - 32;
    dump_bytes("Privkey", key_handle, privkey_size);
    EC_KEY *key = crypto_ec_bytes_to_key(key_handle, privkey_size);

    /* User precense */
    message_add_data(response, (uint8_t *)"\x01", 1);

    /* Counter */
    uint32_t counter = 0x01000000;
    message_add_data(response, (uint8_t *)&counter, 4);
    dump_bytes("counter", (uint8_t *)&counter, 4);

    /* Signature */
    size_t buffer_to_sign_size = 69;
    uint8_t *buffer_to_sign = xmalloc(buffer_to_sign_size);

    /* Buffer to sign */
    memcpy(buffer_to_sign, request.application_param, 32);
    memcpy(buffer_to_sign + 32, "\x01", 1);
    memcpy(buffer_to_sign + 33, &counter, 4);
    memcpy(buffer_to_sign + 37, request.challenge_param, 32);

    /* Digest */
    uint8_t *digest = NULL;
    size_t digest_len =
        crypto_hash(buffer_to_sign, buffer_to_sign_size, &digest);

    /* Signature */
    uint8_t *signature_buffer = NULL;
    size_t signature_len =
        crypto_ec_sign_with_key(key,
                                digest,
                                digest_len,
                                &signature_buffer);

    /* Add it */
    dump_bytes("Tosign", buffer_to_sign, buffer_to_sign_size);
    message_add_data(response, signature_buffer, signature_len);
    dump_bytes("Signature", signature_buffer, signature_len);
    free(buffer_to_sign);


    /* SW */
    uint8_t sw[2] = {SW_NO_ERROR >> 8,
                     SW_NO_ERROR & 0xFF};
    message_add_data(response, sw, 2);
    dump_bytes("SW", sw, 2);

    /* Dump request */
    size_t buffer_dump_size = packet_init_get_bcnt(message->init_packet);
    uint8_t *buffer_dump = xmalloc(buffer_dump_size);
    message_read(message, buffer_dump, 0, buffer_dump_size);
    dump_bytes("Request", buffer_dump, buffer_dump_size);
    free(buffer_dump);

    /* Dump response */
    buffer_dump_size = packet_init_get_bcnt(response->init_packet);
    buffer_dump = xmalloc(buffer_dump_size);
    message_read(response, buffer_dump, 0, buffer_dump_size);
    dump_bytes("Response", buffer_dump, buffer_dump_size);
    free(buffer_dump);

    return response;
}

struct message *raw_authenticate_no_enforce(const struct message *message)
{
    fprintf(stderr, "           no enforce\n");

    (void)message;
    return NULL;
}

struct message *raw_authenticate_handler(const struct message *message)
{
    fprintf(stderr, "       authenticate\n");

    /* Get frame header */
    struct frame_header *header = (struct frame_header *)
                                      message->init_packet->data;

    switch (header->p1)
    {
    case U2F_AUTH_CHECK:
        return raw_authenticate_check(message);
    case U2F_AUTH_ENFORCE:
        return raw_authenticate_enforce(message);
    case U2F_AUTH_NO_ENFORCE:
        return raw_authenticate_no_enforce(message);
    default:
        warnx("Unknow authentification type: %d", header->p1);
        return NULL;
    }

    return NULL;
}
