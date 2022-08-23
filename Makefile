
CORS = corsair
MY_KEYS = create_keys
OTHER_KEYS = take_keys

CFLAGS = -w -Wextra -Wall -I /Users/vduchi/.brew/Cellar/openssl@3/3.0.5/include \
		-L /Users/vduchi/.brew/Cellar/openssl@3/3.0.5/lib -lssl -lcrypto

HEAD = coRSAir.h
SRCS = coRSAir.c free_funcs.c utils.c
SRC_MY_KEYS = create_keys.c free_funcs.c utils.c
SRC_PUB_KEYS = take_keys.c free_funcs.c utils.c

all: $(MY_KEYS) $(OTHER_KEYS) $(CORS)

$(CORS): $(SRCS) $(HEAD)
	@gcc $(CFLAGS) $(SRCS) -o $@
	@echo Created the executable for decrypting two messages!

$(MY_KEYS): $(SRC_MY_KEYS) $(HEAD)
	@gcc $(CFLAGS) $(SRC_MY_KEYS) -o $@
	@echo Created the executable for creating two public keys!

$(OTHER_KEYS): $(SRC_PUB_KEYS) $(HEAD)
	@gcc $(CFLAGS) $(SRC_PUB_KEYS) -o $@
	@echo Created the executable for reading two public keys!

clean:
	@rm -rf $(CORS)
	@rm -rf $(MY_KEYS)
	@rm -rf $(OTHER_KEYS)
	@echo Cleaned the project!

.PHONY: all clean
