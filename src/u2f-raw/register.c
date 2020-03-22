#include <err.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include "authenticate.h"
#include "frame.h"
#include "raw_message.h"
#include "register.h"

#include "../u2f-hid/commands.h"
#include "../u2f-hid/packet.h"
#include "../u2f-hid/message.h"


#include "../crypto.h"
#include "../utils/xalloc.h"


static void register_response_reserved(struct message *response)
{
    /* Reserved buffer */
    const uint8_t reserved[] = { '\x05' };

    /* Add  to response */
    message_add_data(response, reserved, sizeof(reserved));

    /* Log */
    dump_bytes("Reserved", (uint8_t *)"\x05", sizeof(reserved));
}

static void register_response_pubkey(struct message *response,
    const EC_KEY *pubkey)
{
    /* Get pubkey bytes */
    uint8_t *pubkey_buffer = NULL;
    size_t pubkey_size =
        crypto_ec_pubkey_to_bytes(pubkey, &pubkey_buffer);

    /* Add to response */
    message_add_data(response, pubkey_buffer, pubkey_size);

    /* Log */
    dump_bytes("Pubkey", pubkey_buffer, pubkey_size);

    /* Free */
    free(pubkey_buffer);
}


static void register_response_key_handle(struct message *response,
    const uint8_t *key_handle_cipher,
    size_t key_handle_cipher_size)
{
    /* Check size */
    if (key_handle_cipher_size > UINT8_MAX)
    {
        warnx("Key handle size: %zu > %d",
            key_handle_cipher_size,
            UINT8_MAX);
        return;
    }
    /* Get size */
    uint8_t key_handle_cipher_size_byte =
        (uint8_t)key_handle_cipher_size;

    /* Add to response */
    message_add_data(response,
        &key_handle_cipher_size_byte,
        sizeof(key_handle_cipher_size_byte));

    message_add_data(response,
        key_handle_cipher,
        key_handle_cipher_size);
}

static void register_reponse_x509(struct message *response,
    const uint8_t *x509_buffer, size_t x509_buffer_size)
{
    /* Add to reponse */
    message_add_data(response, x509_buffer, x509_buffer_size);

    /* Log */
    dump_bytes("X509", x509_buffer, x509_buffer_size);
}

static void register_response_signature(
    struct message *response,
    const uint8_t *key_handle_cipher,
    size_t key_handle_cipher_size,
    const EC_KEY *pubkey,
    const struct registration_params *params)
{
    /* RFU */
    uint8_t rfu = 0x00;

    /* Get pubkey bytes */
    uint8_t *pubkey_buffer = NULL;
    size_t pubkey_size =
        crypto_ec_pubkey_to_bytes(pubkey, &pubkey_buffer);

    /* Signature */
    size_t buffer_to_sign_size =
        sizeof(rfu)
        + U2F_APP_PARAM_SIZE
        + U2F_CHA_PARAM_SIZE
        + key_handle_cipher_size
        + pubkey_size;

    /* Buffer to sign */
    uint8_t *buffer_to_sign = xmalloc(buffer_to_sign_size);

    /* Fill */
    size_t index = 0;
    /* RFU */
    buffer_to_sign[index] = rfu;
    index += sizeof(rfu);

    /* App Param */
    memcpy(buffer_to_sign + index,
        &params->application_param,
        U2F_APP_PARAM_SIZE);
    index += U2F_APP_PARAM_SIZE;

    /* Challenge Param */
    memcpy(buffer_to_sign + index,
        &params->challenge_param,
        U2F_CHA_PARAM_SIZE);
    index += U2F_CHA_PARAM_SIZE;

    /* Key Handle */
    memcpy(buffer_to_sign + index,
        key_handle_cipher,
        key_handle_cipher_size);
    index += key_handle_cipher_size;

    /* Pubkey */
    memcpy(buffer_to_sign + index,
        pubkey_buffer,
        pubkey_size);
    index += pubkey_size;

    /* Digest */
    uint8_t *digest = NULL;
    size_t digest_len =
        crypto_hash(buffer_to_sign, buffer_to_sign_size, &digest);

    /* Sign */
    uint8_t *signature_buffer = NULL;
    size_t signature_len = crypto_ec_sign(digest,
        digest_len,
        &signature_buffer);

    /* Add to response */
    message_add_data(response, signature_buffer, signature_len);

    /* Log */
    dump_bytes("Signature", signature_buffer, signature_len);

    /* Free */
    free(pubkey_buffer);
    free(buffer_to_sign);
    free(digest);
    free(signature_buffer);
}

static void register_response_sw(struct message *response,
    uint32_t status)
{
    /* SW */
    uint8_t sw[2] = { status >> 8, status & 0xFF };

    /* Add to response */
    message_add_data(response, sw, 2);

    /* Log */
    dump_bytes("SW", sw, 2);
}

static uint8_t *register_build_plain_key_handle(
    EC_KEY *privkey, const struct registration_params *params,
    size_t *size)
{
    /* Get privkey bytes */
    uint8_t *key_handle = NULL;
    uint8_t *key_buffer = NULL;
    size_t key_size =
        crypto_ec_key_to_bytes(privkey, &key_buffer);

    /* Size */
    size_t key_handle_size = key_size + U2F_APP_PARAM_SIZE;
    *size = key_handle_size;

    /* Allocate key_handle */
    key_handle = xmalloc(key_handle_size);

    /* Init key_handle */
    memcpy(key_handle, key_buffer, key_size);
    memcpy(key_handle + key_size, params->application_param,
        U2F_APP_PARAM_SIZE);

    /* Log */
    dump_bytes("Privkey", key_buffer, key_size);
    dump_bytes("Registration params", params->application_param,
        U2F_APP_PARAM_SIZE);
    dump_bytes("Key handle", key_handle, key_handle_size);

    /* Free */
    free(key_buffer);

    return key_handle;
}

static uint8_t *register_encrypt_key_handle(
    const uint8_t *key_handle, size_t key_handle_size, size_t *size)
{
    /* Cipher Key handle */
    uint8_t *key_handle_cipher = NULL;
    size_t key_handle_cipher_size = crypto_aes_encrypt(
            key_handle,
            key_handle_size,
            &key_handle_cipher);

    /* Size */
    *size = key_handle_cipher_size;

    /* Log */
    dump_bytes("Key handle Ciphered size", (uint8_t *)size, sizeof(size));
    dump_bytes("Key handle Ciphered", key_handle_cipher,
        key_handle_cipher_size);

    return key_handle_cipher;
}


struct message *raw_register_handler(const struct message *request)
{
    fprintf(stderr, "       Register\n");

    /* Request */
    struct registration_params params;
    message_read(request, (uint8_t *)&params,
        U2F_APDU_HEADER_SIZE, sizeof(struct registration_params));

    /* New key */
    EC_KEY *privkey = crypto_ec_generate_key();
    EC_KEY *pubkey = crypto_ec_pubkey_from_priv(privkey);

    /* Start Response */
    struct message *response =
        message_new_blank(request->init_packet->cid, CMD_MSG);

    /* Reserved */
    register_response_reserved(response);

    /* Pubkey */
    register_response_pubkey(response, pubkey);

    /* Key handle */
    size_t key_handle_size = 0;
    uint8_t *key_handle = register_build_plain_key_handle(
        privkey,
        &params,
        &key_handle_size
        );

    /* Cipher Key handle */
    size_t key_handle_cipher_size = 0;
    uint8_t *key_handle_cipher = register_encrypt_key_handle(
        key_handle,
        key_handle_size,
        &key_handle_cipher_size
    );

    /* Key handle */
    register_response_key_handle(response,
        key_handle_cipher,
        key_handle_cipher_size);

    /* X509 */
    uint8_t *x509_buffer = NULL;
    size_t x509_buffer_size = crypto_x509_get_bytes(&x509_buffer);
    register_reponse_x509(response, x509_buffer, x509_buffer_size);

    /* Signature */
    register_response_signature(response,
        key_handle_cipher,
        key_handle_cipher_size,
        pubkey,
        &params);

    /* SW */
    register_response_sw(response, SW_NO_ERROR);

    /* Dump request */
    size_t request_buffer_size =
        packet_init_get_bcnt(response->init_packet);
    uint8_t *request_buffer = xmalloc(request_buffer_size);
    message_read(response, request_buffer, 0, request_buffer_size);
    dump_bytes("Message", request_buffer, request_buffer_size);

    /* Dump response */
    size_t response_buffer_size =
        packet_init_get_bcnt(response->init_packet);
    uint8_t *reponse_buffer = xmalloc(response_buffer_size);
    message_read(response, reponse_buffer, 0, response_buffer_size);
    dump_bytes("Message", reponse_buffer, response_buffer_size);

    /* Free */
    EC_KEY_free(privkey);
    EC_KEY_free(pubkey);
    free(key_handle);
    free(key_handle_cipher);
    free(x509_buffer);
    free(request_buffer);
    free(reponse_buffer);

    return response;
}
