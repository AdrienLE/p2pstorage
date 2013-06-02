CXX = g++
MAIDSAFE_DIR ?=	/Users/Adrien/MaidSafe-Common/installed/
BREAKPAD_LINK = $(shell [ `uname` = Darwin ] || echo -lbreakpad)
CXXFLAGS = -std=c++11 -g -I/Users/Adrien/Downloads/b_1_53_0 -I../include -I$(MAIDSAFE_DIR)/include -I$(MAIDSAFE_DIR)/include/breakpad -I./libs -I. -DHAVE_NETINET_IN_H
LDFLAGS = -L../lib -L$(MAIDSAFE_DIR)/lib -L/Users/Adrien/Downloads/b_1_53_0/stage/lib -lJerasure -lmaidsafe_dht-0_32_00 -lmaidsafe_transport-0_02_00 -lmaidsafe_common-0_11_00 -lboost_program_options -lcryptopp -lglog $(BREAKPAD_LINK) -lprotobuf -lboost_thread -lboost_filesystem -lboost_system -lboost_serialization -lthrift

ALL =	jelly

SRC =	$(shell echo *.cpp gen-cpp/jellyinternal_constants.cpp gen-cpp/JellyInternal.cpp gen-cpp/jellyinternal_types.cpp)
OBJ =	$(SRC:.cpp=.o)

all: $(ALL)

clean:
	rm -f core *.o gen-cpp/*.o $(ALL) 

jelly: $(OBJ)
	$(CXX) $(CFLAGS) -o jelly $(OBJ) $(LDFLAGS)
