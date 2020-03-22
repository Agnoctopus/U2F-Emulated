#include <err.h>
#include <poll.h>
#include <stdbool.h>
#include <stdlib.h>

#include "event.h"
#include "uhid.h"


/**
** \brief Run the device by polling the events and handle it
**
** \param fd The fd of the device
** \return 1 on error and 0 on HUP
*/
static int device_loop(int fd)
{
    /* Setup the poll structure */
    struct pollfd pfds[1];
    pfds[0].fd = fd;
    pfds[0].events = POLLIN;

    /* Poll infinitelly the device */
    while (true)
    {
        int ret = poll(pfds, 1, -1);
        if (ret < 0)
        {
            warn("Cannot poll the virtual device");
            return 1;
        }
        if (pfds[0].revents & POLLHUP)
        {
            warn("Received HUP on virtual device");
            break;
        }
        if (pfds[0].revents & POLLIN)
            event_device_handle(fd);
    }

    /* Sould be executed on HUP */

    return 0;
}

/**
** \brief Create a device and run it
**
** \return 0 on success, 1 on error
*/
int device_run(void)
{
    /* Create the virtual device */
    int fd = uhid_device_create();
    if (fd < 0)
        return EXIT_FAILURE;

    /* Run it */
    int ret = device_loop(fd);

    /* Destroy it */
    uhid_device_destroy(fd);

    return ret;
}
