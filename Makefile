# Compiler
CC = clang

# Flags
CFLAGS = -Wall -Wextra -std=c99 -pedantic
CFLAGS += -D_POSIX_C_SOURCE=200809L
LDFLAGS = -lcrypto
TEST_LDLIBS = -lcriterion

# Binary name
BIN = u2f-emulated

# Files
SRC_FILES = \
		main.c \
		crypto.c \
		device/device.c \
		device/uhid.c \
		device/event.c \
		u2f-hid/commands.c \
		u2f-hid/message.c \
		u2f-hid/transaction.c \
		u2f-hid/packet.c \
		u2f-raw/raw_message.c \
		u2f-raw/authenticate.c \
		u2f-raw/register.c \
		utils/xalloc.c

SRC = $(addprefix src/, $(SRC_FILES))

OBJ = ${SRC:.c=.o}

# Test files

TEST = \
		test-crypto

TEST_CRYPTO_OBJS = \
		tests/test-crypto.o \
		src/crypto.o \
		src/utils/xalloc.o

TEST_OBJ = \
	$(TEST_CRYPTO_OBJS)

# Default rule
all: release

# Debug rule
debug: CFLAGS += -g3 -O0
debug: $(BIN)

# Release rule
release: CFLAGS += -Os
release: $(BIN)

$(BIN): $(OBJ)
	$(CC) $(LDFLAGS) $^ -o $@

# Tests rules
test-crypto: $(TEST_CRYPTO_OBJS)

$(TEST):
	$(CC) $(LDFLAGS) $(TEST_LDLIBS) $^ -o $@

# Clean rule
clean:
	$(RM) $(BIN)
	$(RM) $(OBJ)
	$(RM) $(TEST)
	$(RM) $(TEST_OBJ)

# Checks rules
check: CFLAGS += -g3 -O0 -I./src
check: $(TEST)
	@for t in $(TEST); do \
		./$$t -j1 --verbose; \
	done;


check-valgrind: debug
		valgrind \
			--leak-check=full \
			--track-origins=yes \
			./$(BIN)

doc:
	doxygen

# Special rules
.PHONY: all clean release debug check check-valgrind doc
