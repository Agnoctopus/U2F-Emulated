#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/uhid.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "uhid.h"


/**
** \brief The FIDO2/U2F UHID Descriptor
*/
const uint8_t fido_u2f_desc[] =
{
    0x06, 0xD0, 0xF1, /* USAGE_PAGE (FIDO_USAGE_PAGE) */
    0x09, 0x01,       /* USAGE (FIDO_USAGE_PAGE) */
    0xA1, 0x01,       /* COLLECTION (HID_APPLICATION)*/
    0x09, 0x20,       /* USAGE (FIDO_USAGE_DATA_IN) */
    0x15, 0x00,       /* LOGICAL_MINIMUM (0) */
    0x26, 0xFF, 0x00, /* LOGICAL_MAXIMUM (0xff) */
    0x75, 0x08,       /* REPORT_SIZE (8) */
    0x95, 0x40,       /* REPORT_COUNT (HID_INPUT_REPORT_BYTES) */
    0x81, 0x02,       /* INPUT (Data,Var,Abs) */
    0x09, 0x21,       /* USAGE (FIDO_USAGE_DATA_OUT) */
    0x15, 0x00,       /* LOGICAL_MINIMUM (0) */
    0x26, 0xFF, 0x00, /* LOGICAL_MAXIMUM  (255) */
    0x75, 0x08,       /* REPORT_SIZE (8) */
    0x95, 0x40,       /* REPORT_COUNT (HID_OUTPUT_REPORT_BYTES) */
    0x91, 0x02,       /* OUTPUT (Data,Var,Abs) */
    0xC0              /* END_COLLECTION */

};

/**
** \brief Init an uhid event with a type
**
** \param ev The event to init
** \param type The event type
** \return The event
*/
static struct uhid_event *uhid_init_event_type(
        struct uhid_event *ev, uint32_t type)
{
    /* Wipe it */
    memset(ev, 0, sizeof(struct uhid_event));

    /* Event type: Create */
    ev->type = type;

    return ev;
}

int uhid_device_recv_event(int fd, struct uhid_event *ev)
{
    /* Init event */
    memset(ev, 0, sizeof(struct uhid_event));

    /* Recup event */
    ssize_t ret = read(fd, ev, sizeof(struct uhid_event));
    if (ret == 0)
    {
        warnx("Event: Read HUP on uhid-cdev\n");
        return -EFAULT;
    }
    else if (ret < 0)
    {
        warn("Event: Cannot read uhid-cdev\n");
        return -errno;
    }
    else if (ret != sizeof(struct uhid_event))
    {
        warn("Invalid size read from uhid-dev: "
            "%ld != %lu\n", ret, sizeof(struct uhid_event));
        return -EFAULT;
    }

    /* Good */
    return 0;
}

/**
** \brief Send an event to an uhid device
**
** \param fd The fd of the uhid device
** \param ev The event to send
** \return 0 on success, -errno on error
*/
static int uhid_device_send_event(int fd,
        const struct uhid_event *ev)
{
    /* Send it */
    ssize_t ret = write(fd, ev, sizeof(struct uhid_event));

    /* Check */
    if (ret < 0)
    {
        warn("Send event: Cannot write to uhid");
        return -errno;
    }
    else if (ret != sizeof(struct uhid_event))
    {
        warn("Send event: Wrong size written to uhid: "
                "%ld != %lu (Expected)",
                ret, sizeof(struct uhid_event));
        return -errno;
    }

    /* Good */

    return 0;
}

/**
** \brief Init an uhid create event
**
** \param ev The event to init
** \return The event
*/
static struct uhid_event *uhid_init_create_event(
        struct uhid_event *ev)
{
    /* Init type */
    uhid_init_event_type(ev, UHID_CREATE2);

    /* Rest of the event information about our device */
    strcpy((char *)ev->u.create2.name,
            "Virtual FIDO/U2F security Key");
    strcpy((char *)ev->u.create2.phys, "");
    strcpy((char *)ev->u.create2.uniq, "");
    ev->u.create2.rd_size = sizeof(fido_u2f_desc);
    ev->u.create2.bus = BUS_USB;
    ev->u.create2.vendor = 0xFFFF;
    ev->u.create2.product = 0xFFFF;
    ev->u.create2.version = 0;
    ev->u.create2.country = 0;
    memcpy(ev->u.create2.rd_data, fido_u2f_desc,
            sizeof(fido_u2f_desc));

    return ev;
}

/**
** \brief Init an uhid input event
**
** \param ev The event to init
** \param data The data to send
** \param size The size of the data
** \return The event
*/
static struct uhid_event *uhid_init_input_event(
        struct uhid_event *ev, const void *data, uint16_t size)
{
    /* Init type */
    uhid_init_event_type(ev, UHID_INPUT2);

    /* Information */
    ev->u.input2.size = size;
    memcpy(ev->u.input2.data, data, size);

    return ev;
}

int uhid_device_send_input(int fd, const void *data, uint16_t size)
{
    /* Event use to input the device */
    struct uhid_event ev;
    uhid_init_input_event(&ev, data, size);

    /* Send event */
    int ret = uhid_device_send_event(fd, &ev);
    if (ret < 0)
    {
        close(fd);
        return -1;
    }
    return 0;
}

int uhid_device_destroy(int fd)
{
    /* Event use to destroy the device */
    struct uhid_event ev;
    uhid_init_event_type(&ev, UHID_DESTROY);

    /* Send event */
    int ret = uhid_device_send_event(fd, &ev);
    if (ret < 0)
    {
        close(fd);
        return -1;
    }
    return 0;
}

/**
** \brief Open the uhid char device file
**
** \param uhid_path The uhid path
** \return The file descriptor
*/
static int uhid_device_open(const char *uhid_path)
{
    /* Open it */
    int fd = open(uhid_path, O_RDWR | O_CLOEXEC);

    /* Check */
    if (fd < 0)
    {
        warn("UHID open: Cannot open uhid-cdev %s", uhid_path);
        return -errno;
    }

    /* Good */

    return fd;
}

int uhid_device_create_with_path(const char *uhid_path)
{
    /* Open uhid */
    int fd = uhid_device_open(uhid_path);
    if (fd < 0)
        return -1;

    /* Event use to create the device */
    struct uhid_event ev;
    uhid_init_create_event(&ev);

    /* Send event */
    int ret = uhid_device_send_event(fd, &ev);
    if (ret < 0)
    {
        close(fd);
        return -1;
    }
    return fd;
}

int uhid_device_create(void)
{
    return uhid_device_create_with_path("/dev/uhid");
}
