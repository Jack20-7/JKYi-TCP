BLOCK_SERVER_OBJ = $(BIN_DIR)/j_example_tcp_server.o


BLOCK_SERVER = j_example_block_server

all: $(BLOCK_SERVER)

$(BLOCK_SERVER): $(BLOCK_SERVER_OBJ)
	$(CC) -o $(BIN_DIR)/$(BLOCK_SERVER) $(OBJS_DIR)/* $(BLOCK_SERVER_OBJ) $(FLAG)