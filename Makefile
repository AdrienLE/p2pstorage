CXX = clang++
MAIDSAFE_DIR ?=	/usr/local/include
CXXFLAGS = -std=c++11 -g -I../include -I$(MAIDSAFE_DIR)/include -I$(MAIDSAFE_DIR)/include/breakpad -I./libs -I.
LDFLAGS = -L../lib -L$(MAIDSAFE_DIR)/lib -lJerasure -lmaidsafe_dht-0_32_00 -lmaidsafe_transport-0_02_00 -lmaidsafe_common-0_11_00 -lboost_program_options -lcryptopp -lglog -lbreakpad -lprotobuf -lboost_thread -lboost_filesystem -lboost_system -lboost_serialization

ALL =	jellyfish

SRC =	$(shell echo *.cpp)
OBJ =	$(SRC:.cpp=.o)

all: $(ALL)

clean:
	rm -f core *.o $(ALL) 

jellyfish: $(OBJ)
	$(CXX) $(CFLAGS) -o jellyfish $(OBJ) $(LDFLAGS)
