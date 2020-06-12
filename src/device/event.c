#include <err.h>
#include <linux/uhid.h>
#include <stddef.h>
#include <stdio.h>

#include "event.h"
#include "uhid.h"
#include "../u2f-hid/packet.h"
#include "../u2f-hid/message.h"


/**
** \brief Event handler
*/
typedef
void (*event_handler)(int fd, const struct uhid_event *event);

/**
** \brief The output event handler
**
** \param fd The fd of the device
** \param event The event
*/
static void event_output_handler(int fd,
    const struct uhid_event *event)
{
    fprintf(stderr, "UHID_OUTPUT\n");
    printf("0x%hX\n", event->u.output.data[0]);

    /* Get the packet */
    const void *packet = event->u.output.data + 1;
    size_t packet_size = event->u.output.size - 1;

    /* Handle packet */
    struct message *response =
        packet_handle(packet, packet_size);

    /* Send the response messageif exist */
    if (response != NULL)
    {
        message_send(fd, response);
        message_free(response);
    }
}

/**
** \brief The start event handler
**
** \param fd The fd of the device
** \param event The event
*/
static void event_start_handler(int fd,
    const struct uhid_event *event)
{
    fprintf(stderr, "UHID_START\n");
    (void)fd;
    (void)event;
}

/**
** \brief The stop event handler
**
** \param fd The fd of the device
** \param event The event
*/
static void event_stop_handler(int fd,
    const struct uhid_event *event)
{
    fprintf(stderr, "UHID_STOP\n");
    (void)fd;
    (void)event;
}

/**
** \brief The open event handler
**
** \param fd The fd of the device
** \param event The event
*/
static void event_open_handler(int fd,
    const struct uhid_event *event)
{
    fprintf(stderr, "UHID_OPEN\n");
    (void)fd;
    (void)event;
}

/**
** \brief The close event handler
**
** \param fd fd The fd of the device
** \param event The event
*/
static void event_close_handler(int fd,
    const struct uhid_event *event)
{
    fprintf(stderr, "UHID_CLOSE\n");
    (void)fd;
    (void)event;
}

/**
** \brief Get the event handler associate with an event type
**
** \param event The event type
** \return The handler
*/
static event_handler event_get_handler(uint32_t event)
{
    struct event_entry
    {
        uint32_t event;
        event_handler handler;
    };
    static const struct event_entry event_entries[] =
    {
        { UHID_START,   event_start_handler     },
        { UHID_STOP,    event_stop_handler      },
        { UHID_OPEN,    event_open_handler      },
        { UHID_CLOSE,   event_close_handler     },
        { UHID_OUTPUT,  event_output_handler    }
    };
    static size_t event_entries_length =
        sizeof(event_entries) / sizeof(struct event_entry);

    /* Loop through the supported events */
    for (size_t i = 0; i < event_entries_length; ++i)
    {
        if (event == event_entries[i].event)
            return event_entries[i].handler;
    }
    return NULL;
}

void event_device_handle(int fd)
{
    /* Get the event */
    struct uhid_event event;
    uhid_device_recv_event(fd, &event);

    /* Get the handler for the event */
    event_handler handler = event_get_handler(event.type);
    if (handler == NULL)
    {
        warnx("No handler for the event %u", event.type);
        return;
    }

    /* Handle it */
    handler(fd, &event);
}
