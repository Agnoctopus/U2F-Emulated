#ifndef UHID_H
#define UHID_H

#include <linux/uhid.h>
#include <stdint.h>


/**
** \brief Send input data to the kernel
**
** \param fd The fd of the device
** \param data The data to send
** \return 0 on sucess
*/
int uhid_device_send_input(int fd, const void *data, uint16_t size);

/**
** \brief Receive an uhid event from a device
**
** \param The fd of the device
** \param ev The event to fill
** \return 0 on success, -errno on error
*/
int uhid_device_recv_event(int fd, struct uhid_event *ev);

/**
** \brief Destroy an uhid device
**
** \param fd The fd of the device
** \return 0 on sucess, -1 on error
*/
int uhid_device_destroy(int fd);

/**
** \brief Create an uhid usb device
**
** \param uhid_path The path of the uhid, should be /dev/uhid in most
**        cases
** \return The fd of the device
*/
int uhid_device_create_with_path(const char *uhid_path);

/**
** \brief Create an uhid usb device with the defautl uhid path
**        /dev/uhid
**
** \param uhid_path The path of the uhid, should be /dev/uhid in most
**        cases
** \return The fd of the device
*/
int uhid_device_create(void);

#endif
