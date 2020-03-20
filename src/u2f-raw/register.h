#ifndef REGISTER_H
#define REGISTER_H

#include "../u2f-hid/message.h"


struct message *raw_register_handler(const struct message *message);


#endif
