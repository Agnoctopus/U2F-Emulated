#ifndef AUTHENTICATE_H
#define AUTHENTICATE_H

#include "../u2f-hid/message.h"

struct message *raw_authenticate_handler(const struct message *message);

#endif
