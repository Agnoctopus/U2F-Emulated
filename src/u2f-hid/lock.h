#ifndef LOCK_H
#define LOCK_H

#include <stdbool.h>
#include <stdint.h>

#define LOCKED_TIME

/**
** \brief Check if the deice is locked
**
** \return true: locked, false: not locked
*/
bool locked(void);

/**
**
*/
bool locked_cid(uint32_t cid);

/**
**
*/
bool lock_cid(uint32_t cid);

#endif
