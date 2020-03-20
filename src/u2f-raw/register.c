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


struct message *raw_register_handler(const struct message *message)
{
    fprintf(stderr, "       Register\n");

    /* Request */
    struct registration_request request;
    message_read(message, (uint8_t *)&request,
        7, sizeof(struct registration_request));

    /* New key */
    EC_KEY *privkey = crypto_ec_generate_key();
    EC_KEY *pubkey = crypto_ec_pubkey_from_priv(privkey);

    struct message *response =
        message_new_blank(message->init_packet->cid, CMD_MSG);

    /* Reserved */
    message_add_data(response, (uint8_t *)"\x05", 1);
    dump_bytes("Reserved", (uint8_t *)"\x05", 1);

    /* Pubkey */
    uint8_t *pubkey_buffer = NULL;
    size_t pubkey_size =
        crypto_ec_pubkey_to_bytes(pubkey, &pubkey_buffer);
    message_add_data(response, pubkey_buffer, pubkey_size);
    dump_bytes("Pubkey", pubkey_buffer, pubkey_size);


    /* Key handle */
    uint8_t *key_handle = NULL;
    uint8_t *key_buffer = NULL;
    size_t key_size =
        crypto_ec_key_to_bytes(privkey, &key_buffer);

    dump_bytes("Privkey", key_buffer, key_size);
    key_handle = xmalloc(32 + key_size);

    memcpy(key_handle, key_buffer, key_size);
    memcpy(key_handle + key_size, request.application_param, 32);

    /* Cipher */
    uint8_t *key_handle_cipher = NULL;
    size_t key_handle_cipher_size = crypto_aes_encrypt(
            key_handle,
            32 + key_size,
            &key_handle_cipher);

    uint8_t value = (uint8_t)key_handle_cipher_size;
    dump_bytes("Key handle", key_handle, key_size + 32);
    message_add_data(response, &value, 1);
    dump_bytes("Key handle size", &value, 1);
    message_add_data(response, key_handle_cipher, key_handle_cipher_size);
    dump_bytes("Key handle Ciphered", key_handle_cipher, key_handle_cipher_size);

    /* X509 */
    uint8_t *x509_buffer = NULL;
    size_t x509_size = crypto_x509_get_bytes(&x509_buffer);
    message_add_data(response, x509_buffer, x509_size);
    dump_bytes("X509", x509_buffer, x509_size);

    /* Signature */
    size_t buffer_to_sign_size = 65 + x509_size + key_handle_cipher_size + pubkey_size;
    uint8_t *buffer_to_sign = xmalloc(buffer_to_sign_size);

    /* Buffer to sign */
    buffer_to_sign[0] = 0x00;
    memcpy(buffer_to_sign + 1, request.application_param, 32);
    memcpy(buffer_to_sign + 33, request.challenge_param, 32);
    memcpy(buffer_to_sign + 65, key_handle_cipher, key_handle_cipher_size);
    memcpy(buffer_to_sign + 65 + key_handle_cipher_size, pubkey_buffer, pubkey_size);
    free(key_handle);

    /* Digest */
    uint8_t *digest = NULL;
    size_t digest_len =
        crypto_hash(buffer_to_sign, buffer_to_sign_size, &digest);
    free(buffer_to_sign);

    /* Signature */
    uint8_t *signature_buffer = NULL;
    size_t signature_len = crypto_ec_sign(digest, digest_len, &signature_buffer);

    message_add_data(response, signature_buffer, signature_len);
    dump_bytes("Signature", signature_buffer, signature_len);

    /* SW */
    uint8_t sw[2] = { SW_NO_ERROR >> 8, SW_NO_ERROR & 0xFF };
    message_add_data(response, sw, 2);
    dump_bytes("SW", sw, 2);

    /* Dimp response */
    size_t buffer_dump_size = packet_init_get_bcnt(response->init_packet);
    uint8_t *buffer_dump = malloc(buffer_dump_size);
    message_read(response, buffer_dump, 0, buffer_dump_size);
    dump_bytes("Message", buffer_dump, buffer_dump_size);
    free(buffer_dump);

    return response;
}
