#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "commands.h"
#include "transaction.h"
#include "../utils/xalloc.h"


/**
** \brief Represent a transaction: a request following by a respond
*/
struct transaction
{
    time_t start_time; /**< The start time */
    struct message *request; /**< The request  */
};

/**
** \brief The current transaction
*/
struct transaction *transaction_current = NULL;

bool transaction_check_timeout(int fd)
{
    (void)fd;
    return true;
}

bool transaction_on_going(void)
{
    return transaction_current != NULL;
}

bool transaction_cid_in(uint32_t cid)
{
    return transaction_current->request->init_packet->cid == cid;
}

void transaction_start(struct message *message)
{
    /* Stop old  */
    transaction_stop();

    /* Allocate */
    transaction_current = xmalloc(sizeof(struct transaction));

    /* Init */
    transaction_current->request = message;
    transaction_current->start_time = time(NULL);
}

void transaction_stop(void)
{
    /* Free old */
    free(transaction_current);

    transaction_current = NULL;
}

struct message *transaction_request(void)
{
    if (transaction_current == NULL)
        return NULL;
    return transaction_current->request;
}
