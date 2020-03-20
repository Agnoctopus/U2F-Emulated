#ifndef TRANSACTION_H
#define TRANSACTION_H

#include <stdbool.h>
#include <stddef.h>

#include "packet.h"
#include "message.h"


#define TIMEOUT_SECONDS 5

/**
** \brief Check if the possible current transaction has timeout and
**        if so, send a timeout error to the requester
**
** \param fd The device fd
** \return true: transaction has timeout
*/
bool transaction_check_timeout(int fd);

/**
** \brief Check if a transaction is on going
**
** \return true: transaction on going
*/
bool transaction_on_going(void);

/**
** \brief Chec if a transaction is on going with a cid
**
** \param The cid we want to check
** \return true: a transaction is ongoin with the cid
*/
bool transaction_cid_in(uint32_t cid);

/**
** \brief Start a transaction
**
** \param message The actual request message
*/
void transaction_start(struct message *message);
/**
** \brief Stop the actual transaction
*/
void transaction_stop(void);

/**
** \brief Get the current trasaction request
*/
struct message *transaction_request(void);

#endif
