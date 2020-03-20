#include "crypto.h"
#include "device/device.h"


int main(void)
{
    /* Crypto setup */
    crypto_setup();

    /* Device */
    int ret = device_run();

    /* Crypto release */
    crypto_release();

    return ret;
}
