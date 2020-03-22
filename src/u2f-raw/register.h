#ifndef REGISTER_H
#define REGISTER_H

#include "../u2f-hid/message.h"


/**
** \brief Handle registration request
**
** \param request The registration request message
** \return The response or null if no response
*/
struct message *raw_register_handler(const struct message *request);

#endif
