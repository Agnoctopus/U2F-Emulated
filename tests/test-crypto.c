#include <criterion/criterion.h>

#include "crypto.h"


Test(hash, hash_0)
{
    /* Given */
    const char data[] = "hash";
    size_t data_len = sizeof(data) - 1;
    const char hash_ref[] = "\xd0\x4b\x98\xf4\x8e\x8f\x8b\xcc\x15"
        "\xc6\xae\x5a\xc0\x50\x80\x1c\xd6\xdc\xfd\x42\x8f\xb5\xf9"
        "\xe6\x5c\x4e\x16\xe7\x80\x73\x40\xfa";
    uint8_t *hash = NULL;
    size_t hash_len = 0;

    /* When */
    hash_len = crypto_hash(data, data_len, &hash);

    /* Then */
    cr_assert_eq(32, hash_len);
    cr_assert_arr_eq(hash, hash_ref, 32);
}

Test(key, key_bytes_key)
{
    /* Given */
    EC_KEY *key_ref = crypto_ec_generate_key();
    char *pem_ref = crypto_ec_privkey_to_pem(key_ref);
    unsigned char *buffer = NULL;

    /* When */
    int buffer_len = crypto_ec_key_to_bytes(key_ref, &buffer);
    EC_KEY *key = crypto_ec_bytes_to_key(buffer, buffer_len);

    /* Then */
    char *pem = crypto_ec_privkey_to_pem(key);
    cr_assert_str_eq(pem, pem_ref);
}

Test(aes, aes_0)
{
    /* Given */
    const char data_ref[] = "secret";
    size_t data_ref_len = sizeof(data_ref);
    uint8_t *cipher = NULL;
    size_t cipher_len;
    uint8_t *plaintext = NULL;
    size_t plaintext_len;

    /* When */
    cipher_len = crypto_aes_encrypt((const unsigned char *)data_ref,
        data_ref_len, &cipher);
    plaintext_len = crypto_aes_decrypt(cipher, cipher_len,
            &plaintext);

    /* Then */
    cr_assert_eq(plaintext_len, data_ref_len);
    cr_assert_str_eq((char*)plaintext, data_ref);
}

Test(sign_, sign_0)
{
    /* Given */
    const char data[] = "Sign me";
    size_t data_len = sizeof(data);
    EC_KEY *key = crypto_ec_generate_key();
    unsigned char *signature = NULL;

    /* When */
    unsigned int signature_len =
        crypto_ec_sign_with_key(key, (const unsigned char *)data,
            data_len, &signature);

    /* Then */
    cr_assert_neq(signature_len, 0);
}
