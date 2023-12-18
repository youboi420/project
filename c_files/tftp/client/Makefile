HEADERS_PATH = includes/
HEADERS = $(HEADERS_PATH)*
SRC_PATH = src/
SRC = $(SRC_PATH)*
BUILD = build/
TEST_PATH = TEST/

TEST1 = $(TEST_PATH)/test1.txt
TEST2 = $(TEST_PATH)/test2.txt

FLAGS = -Wall -ansi -pedantic
OBJECT = client

init:
	mkdir $(HEADERS_PATH)
	mkdir $(SRC_PATH)
	mkdir $(TEST_PATH)

$(OBJECT): $(SRC) $(HEADERS)
	gcc $(SRC) -I $(HEADERS) -o $(BUILD)$(OBJECT) 
#	gcc $(SRC) -I $(HEADERS) -o $(OBJECT) $(FLAGS)

# clear: $(SRC) $(HEADERS)
# 	rm $(OBJECT)
