#ifndef CRYPTO_H
#define CRYPTO_H

#include <openssl/ec.h>


/**
** \brief Hash data using sha256
**
** \param data The data
** \param data_len The data length
** \param hash The ref buffer to put the hash
** \return The size of the hash
*/
size_t crypto_hash(const void *data, size_t data_len,
        unsigned char **hash);

/**
** \brief Generate an ec pair key
**
** \return The generated ec pair key
*/
EC_KEY *crypto_ec_generate_key(void);

/**
** \brief Get the pem reprensentation of a private key
**
** \param privkey The private key
** \return The pem representation
*/
char *crypto_ec_privkey_to_pem(EC_KEY *privkey);

/**
** \brief Get the pem reprensentation of a public key
**
** \param pubkey The public key
** \return The pem representation
*/
char *crypto_ec_pubkey_to_pem(EC_KEY *pubkey);

/**
** \brief Get the public key from the private key
**
** \param privkey the privkey
** \return The public key
*/
EC_KEY *crypto_ec_pubkey_from_priv(EC_KEY *privkey);

/**
** \brief Get the public ec key bytes
**
** \param key The ec key
** \param buffer The buffer use to put the bytes
** \return The size of the buffer
*/
size_t crypto_ec_pubkey_to_bytes(const EC_KEY *key,
    unsigned char **buffer);

/**
** \brief Get the ec key bytes
**
** \param key The key
** \param buffer The buffer use to put the bytes
** \return The size of the buffer
*/
int crypto_ec_key_to_bytes(EC_KEY *key, unsigned char **buffer);

/**
** \brief Get the ec key from ec key bytes
**
** \param buffer The buffer containing the ec key bytes
** \param size The size of the buffer
** \return The ec key
*/
EC_KEY *crypto_ec_bytes_to_key(const unsigned char *buffer,
    long size);

/**
** \brief Sign a digest with a specific key
**
** \param key The ec key
** \param digest The digest
** \param digest_len The digest len
** \param signature The ref buffer to put the signature
** \return The size of the signature, 0 on error
*/
unsigned int crypto_ec_sign_with_key(EC_KEY *key,
    const unsigned char *digest,
    int digest_len,
    unsigned char **signature);

/**
** \brief Sign a digest
**
** \param digest The digest
** \param digest_len The digest length
** \param signature The ref buffer to put the signature
** \return The size of the signature, 0 on error
*/
unsigned int crypto_ec_sign(const unsigned char *digest,
    int digest_len,
    unsigned char **signature);

/**
** \brief Encrypt data using aes
**
** \param data The data to encrypt
** \param data_len The data size
** \param buffer The resulting buffer where cipher data is put
** \return The size of the buffer
*/
size_t crypto_aes_encrypt(const unsigned char *data, int data_len,
        unsigned char **buffer);

/**
** \brief Decrypt data using aes
**
** \param data The data to decrypt
** \param size The data size
** \param buffer The resulting buffer where clear data is put
** \return The size of the buffer
*/
size_t crypto_aes_decrypt(const unsigned char *data, int size,
        unsigned char **buffer);

/**
** \brief Get the X509 attestation bytes
**
** \param buffer The buffer to put the bytes
** \return The buffer length
*/
int crypto_x509_get_bytes(unsigned char **buffer);

/**
** \brief Setup all the crypto stuffs
*/
int crypto_setup(void);

/**
** \brief Release all the crypto stuffs
*/
void crypto_release(void);

#endif
