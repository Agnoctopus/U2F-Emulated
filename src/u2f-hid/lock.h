#ifndef LOCK_H
#define LOCK_H

#include <stdbool.h>
#include <stdint.h>


#define LOCKED_TIME 4

/**
** \brief Check if the device is locked
**
** \return true: locked, false: not locked
*/
bool locked(void);

/**
** // TODO
*/
bool locked_cid(uint32_t cid);

/**
** // TODO
*/
bool lock_cid(uint32_t cid);

#endif
