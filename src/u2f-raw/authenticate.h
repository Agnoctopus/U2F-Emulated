#ifndef AUTHENTICATE_H
#define AUTHENTICATE_H

#include "../u2f-hid/message.h"


/**
** \brief Handle authentification request
**
** \param request The authentification request message
** \return The response
*/
struct message *raw_authenticate_handler(
    const struct message *request);

#endif
