#include <err.h>
#include <fcntl.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/ecdsa.h>
#include <openssl/pem.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "crypto.h"
#include "utils/xalloc.h"


/**
** \brief X509 attestation certificate
*/
static X509 *g_x509 = NULL;

/**
** \brief X509 attestation private key
*/
static EC_KEY *g_privkey = NULL;

/**
** \brief X509 attestation public key
*/
static EC_KEY *g_pubkey = NULL;

/**
** \brief AES KEY
*/
static uint8_t g_aes_key[32] = { 0 };

/**
** \brief AES IV
*/
static uint8_t g_aes_iv[16] = { 0 };


size_t crypto_hash(const void *data, size_t data_len,
        unsigned char **hash)
{
    /* Init */
    SHA256_CTX sha256;
    if (SHA256_Init(&sha256) != 1)
    {
        /* Log */
        warnx("Failed to init sha256");
        return 0;
    }

    /* Allocate hash buffer */
    *hash = xmalloc(SHA256_DIGEST_LENGTH);

    /* Update */
    if (SHA256_Update(&sha256, data, data_len) != 1)
    {
        /* Log */
        warnx("Failed to update sha256");

        /* Release */
        free(hash);

        return 0;
    }

    /* Finish */
    if(SHA256_Final(*hash, &sha256) != 1)
    {
        /* Log */
        warnx("Failed to update sha256");

        /* Release */
        free(hash);

        return 0;
    }

    return SHA256_DIGEST_LENGTH;
}

EC_KEY *crypto_ec_generate_key(void)
{
    /* Prepare ec key */
    EC_KEY *key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (key == NULL)
    {
        /* Log */
        warnx("Failed to instantiate new ec Key");
        return NULL;
    }

    /* Generate */
    if (EC_KEY_generate_key(key) != 1)
    {
        /* Log */
        warnx("Failed to instantiate new ec Key");

        /* Release */
        EC_KEY_free(key);

        return NULL;
    }
    return key;
}

/**
** \brief Get the pem representation from a keybio
**
** \param keybio The bio containing the pub/priv key
** \return The prem reprensentation
*/
static char *crypto_biokey_to_pem(BIO* keybio)
{
    /* Allocate buffer */
    int bio_length = BIO_pending(keybio);
    if (bio_length == 0)
    {
        warnx("Failed to retrieves pem length");
        return NULL;
    }
    char *buffer = xmalloc(bio_length + 1);

    /* Fill buffer */
    if (BIO_read(keybio, buffer, bio_length) != bio_length)
    {
        /* Log */
        warnx("Failed to retrieves pem length");

        /* Release */
        free(buffer);

        return NULL;
    }

    /* Null terminated */
    buffer[bio_length] = '\0';

    return buffer;
}

char *crypto_ec_privkey_to_pem(EC_KEY *privkey)
{
    /* Bio */
    BIO *privkeybio = BIO_new(BIO_s_mem());
    if (privkeybio == NULL)
    {
        warnx("Failed to create new bio");
        return NULL;
    }
    /* Write privkey yo the bio */
    PEM_write_bio_ECPrivateKey(privkeybio, privkey, NULL, NULL,
        0, 0, NULL);

    /* Get pem */
    char *buffer = crypto_biokey_to_pem(privkeybio);

    /* Free */
    BIO_free_all(privkeybio);

    if (buffer == NULL)
        warnx("Failed get pem from bio");

    return buffer;
}

char *crypto_ec_pubkey_to_pem(EC_KEY *pubkey)
{
    /* Bio */
    BIO *pubkeybio = BIO_new(BIO_s_mem());
    if (pubkeybio == NULL)
    {
        warnx("Failed to create new bio");
        return NULL;
    }
    /* Write pubkey yo the bio */
    PEM_write_bio_EC_PUBKEY(pubkeybio, pubkey);

    /* Get pem */
    char *buffer = crypto_biokey_to_pem(pubkeybio);

    /* Free */
    BIO_free_all(pubkeybio);

    if (buffer == NULL)
        warnx("Failed get pem from bio");

    return buffer;
}


EC_KEY *crypto_ec_pubkey_from_priv(EC_KEY *privkey)
{
    /* Bio needed */
    BIO *pubkeybio = BIO_new(BIO_s_mem());
    if (pubkeybio == NULL)
    {
        warnx("Failed to create new bio");
        return NULL;
    }
    /* Write pubkey to the bio  */
    if (PEM_write_bio_EC_PUBKEY(pubkeybio, privkey) != 1)
    {
        /* Log */
        warnx("Failed to write pubkey to bio");

        /* Release */
        BIO_free_all(pubkeybio);

        return NULL;
    }

    /* Get pubkey */
    EC_KEY *pubkey = EC_KEY_new() ;
    pubkey = PEM_read_bio_EC_PUBKEY(pubkeybio, &pubkey, NULL, NULL);

    /* Free */
    BIO_free_all(pubkeybio);

    if (pubkey == NULL)
        warnx("Failed to read pubkey from bio");

    return pubkey;
}

size_t crypto_ec_pubkey_to_bytes(const EC_KEY *key,
    unsigned char **buffer)
{
    /* bignum context */
    BN_CTX *bn_ctx = BN_CTX_new();
    if (bn_ctx == NULL)
    {
        warnx("Failed create bn ctx");
        return 0;
    }

    size_t size = EC_KEY_key2buf(key,
            POINT_CONVERSION_UNCOMPRESSED,
            buffer,
            bn_ctx);

    /* Free */
    BN_CTX_free(bn_ctx);

    if (size == 0)
        warnx("Failed get key from buf");

    return size;
}

int crypto_ec_key_to_bytes(EC_KEY *key, unsigned char **buffer)
{
    /* Init */
    *buffer = NULL;

    /* Get bytes */
    int size = i2d_ECPrivateKey(key, buffer);
    if (size == 0)
    {
        warn("Failed to get ec key bytes");
        return 0;
    }

    return size;
}

EC_KEY *crypto_ec_bytes_to_key(const unsigned char *buffer,
    long size)
{
    /* prepare curve and key */
    EC_KEY *key = NULL;

    /* Get key */
    key = d2i_ECPrivateKey(&key, &buffer, size);
    if (key == NULL)
    {
        warn("Failed to get key from ec key bytes");
        return 0;
    }

    return key;
}

unsigned int crypto_ec_sign(const unsigned char *digest,
    int digest_len,
    unsigned char **signature)
{
    return crypto_ec_sign_with_key(g_privkey,
        digest, digest_len, signature);
}

unsigned int crypto_ec_sign_with_key(EC_KEY *key,
    const unsigned char *digest,
    int digest_len,
    unsigned char **signature)
{
    /* Signature length  */
    *signature = NULL;
    int ret_size = ECDSA_size(key);
    if (ret_size <= 0)
    {
        /* Log */
        warnx("Failed to get signature len");
        return 0;
    }
    unsigned int signature_len = ret_size;

    /* Signature buffer */
    *signature = OPENSSL_malloc(signature_len);
    if (*signature == NULL)
        return 0;

    /* Sign */
    int sign_ret = ECDSA_sign(0,
            digest,
            digest_len,
            *signature,
            &signature_len,
            key);

    /* Sign check */
    if (sign_ret != 1)
    {
        /* Log */
        warnx("Failed to sign");

        /* Release */
        free(*signature);
        *signature = NULL;
        return 0;
    }

    /* Verify the signature */
    int verify_ret = ECDSA_verify(0,
            digest,
            digest_len,
            *signature,
            signature_len,
            key);

    /* Verify check */
    if (verify_ret != 1)
    {
        /* Log */
        if (verify_ret == 0)
            warnx("Failed to sign correctly");
        else
            warnx("Failed to verify the signature");

        /* Release */
        free(*signature);
        *signature = NULL;
        return 0;
    }

    /* Good */

    return signature_len;
}


/**
** \brief Open the privkey file
**
** \param pathname The pathname
** \return The File ptr
*/
static FILE *crypto_privkey_open(const char *pathname)
{
    /* Open */
    int fd = open(pathname, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
    {
        warn("Privkey: Failed to open %s", pathname);
        return NULL;
    }

    /* Fdopen */
    FILE * fp = fdopen(fd, "rb");
    if (fp == NULL)
    {
        warn("Privkey: Failed to fdopen %s", pathname);
        return NULL;
    }

    return fp;
}

X509 *crypto_x509_from_path(const char *pathname)
{
    /* Open */
    FILE *fp = crypto_privkey_open(pathname);
    if (fp == NULL)
        return NULL;

    /* X509  */
    X509 *x509 = X509_new() ;
    x509 = PEM_read_X509(fp, &x509, NULL, NULL);

    /* Close */
    fclose(fp);

    return x509;
}

size_t crypto_aes_encrypt(const unsigned char *data, int data_len,
        unsigned char **buffer)
{
    /* Cipher context */
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL)
    {
        warnx("Failed to create a ciper context");
        return 0;
    }

    /* Init operation */
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(),
        NULL, NULL, NULL) != 1)
    {
        /* Log */
        warnx("Failed to set the aes context");

        /* Free */
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    /* Init and key */
    if (EVP_EncryptInit_ex(ctx, NULL,
        NULL, g_aes_key, g_aes_iv) != 1)
    {
        /* Log */
        warnx("Failed to init encryption");

        /* Free */
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    /* Allocate */
    *buffer = xmalloc(data_len + 32);
    int len = 0;

    /* Encrypt */
    if (EVP_EncryptUpdate(ctx, *buffer, &len, data, data_len) != 1)
    {
        /* Log */
        warnx("Failed to update encryption");

        /* Free */
        EVP_CIPHER_CTX_free(ctx);
        free(*buffer);

        return 0;
    }
    size_t result_len = len;

    if (EVP_EncryptFinal_ex(ctx, (*buffer) + len, &len) != 1)
    {
        /* Log */
        warnx("Failed to final encryption");

        /* Free */
        EVP_CIPHER_CTX_free(ctx);
        free(*buffer);

        return 0;
    }
    result_len += len;

    /* Free */
    EVP_CIPHER_CTX_free(ctx);

    return result_len;;
}


size_t crypto_aes_decrypt(const unsigned char *data, int size,
        unsigned char **buffer)
{
    /* Cipher context */
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL)
    {
        warnx("Failed to create a ciper context");
        return 0;
    }

    /* Init operation */
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(),
        NULL, NULL, NULL) != 1)
    {
        /* Log */
        warnx("Failed to set the aes context");

        /* Free */
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    /* Init and key */
    if (EVP_DecryptInit_ex(ctx, NULL,
            NULL, g_aes_key, g_aes_iv) != 1)
    {
        /* Log */
        warnx("Failed to init decryption");

        /* Free */
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    /* Allocate */
    *buffer = xmalloc(size + 32);
    int len = 0;
    size_t result_len = 0;

    /* Decrypr */
    if (EVP_DecryptUpdate(ctx, *buffer, &len, data, size) != 1)
    {
        /* Log */
        warnx("Failed to update decryption");

        /* Free */
        EVP_CIPHER_CTX_free(ctx);
        free(*buffer);

        return 0;
    }
    result_len = len;

    if (EVP_DecryptFinal_ex(ctx, (*buffer) + len, &len) != 1)
    {
        /* Log */
        warnx("Failed to final decryption");

        /* Free */
        EVP_CIPHER_CTX_free(ctx);
        free(*buffer);

        return 0;
    }
    result_len += len;

    /* Free */
    EVP_CIPHER_CTX_free(ctx);

    return result_len;
}

int crypto_x509_get_bytes(unsigned char **buffer)
{
    *buffer = NULL;
    return i2d_X509(g_x509, buffer);
}

/**
** \brief Open the privkey file
**
** \param pathname The pathname
** \return The File ptr
*/
static FILE *crypto_open(const char *pathname)
{
    /* Open */
    int fd = open(pathname, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
    {
        warn("Privkey: Failed to open %s", pathname);
        return NULL;
    }

    /* Fdopen */
    FILE *fp = fdopen(fd, "rb");
    if (fp == NULL)
    {
        warn("Privkey: Failed to fdopen %s", pathname);
        return NULL;
    }

    return fp;
}

/**
** \brief Get the private key from path
**
** \param pathname The pathname
** \return The private key
*/
static EC_KEY *crypto_ec_privkey_from_path(const char *pathname)
{
    /* Open */
    FILE *fp = crypto_open(pathname);
    if (fp == NULL)
        return NULL;

    /* EC_Key */
    EC_KEY *privkey = EC_KEY_new() ;
    privkey = PEM_read_ECPrivateKey(fp, &privkey, NULL, NULL);

    /* Close */
    fclose(fp);

    return privkey;
}

static int crypto_aes_setup(void)
{
    /* Open */
    FILE *fp = crypto_open("keys/aes-key");

    /* Key and iv */
    fread(g_aes_key, 32, 1, fp);
    fread(g_aes_iv, 16, 1, fp);

    /* Close */
    fclose(fp);

    return 0;
}

int crypto_setup(void)
{
    /* X509 */
    g_x509 = crypto_x509_from_path("keys/server.pem");

    /* Pub/Prib Key */
    g_privkey =
        crypto_ec_privkey_from_path("keys/prime256v1-key.pem");
    g_pubkey = crypto_ec_pubkey_from_priv(g_privkey);

    /* AES */
    crypto_aes_setup();

    return 0;
}

void crypto_release(void)
{
    /* X509 */
    X509_free(g_x509);

    /* Pub/Prib Key */
    EC_KEY_free(g_privkey);
    EC_KEY_free(g_pubkey);
}
