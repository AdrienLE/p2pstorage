CXX = g++
MAIDSAFE_DIR ?=	/Users/Adrien/MaidSafe-Common/installed/
BREAKPAD_LINK = $(shell [ `uname` = Darwin ] || echo -lbreakpad)
CXXFLAGS = -std=c++11 -g -isystem ./boost_extension -isystem /Users/Adrien/Downloads/b_1_53_0 -isystem ../include -isystem $(MAIDSAFE_DIR)/include -isystem $(MAIDSAFE_DIR)/include/breakpad -I./libs -I. -DHAVE_NETINET_IN_H -fno-common -Wall -Wextra -Wformat=2 -Winit-self -Winline -Wp,-D_FORTIFY_SOURCE=2 -Wpointer-arith -Wlarger-than-65500 -Wmissing-declarations -Wmissing-format-attribute -Wmissing-noreturn -Wsign-compare -Wunreachable-code -Wwrite-strings -Wfloat-equal -Wno-unused-function -Wno-unused-parameter -O0 -fpermissive
LDFLAGS = -L../lib -L$(MAIDSAFE_DIR)/lib -L/Users/Adrien/Downloads/b_1_53_0/stage/lib -lmaidsafe_dht-0_32_00 -lmaidsafe_transport-0_02_00 -lmaidsafe_common-0_11_00 -lboost_program_options -lcryptopp -lglog $(BREAKPAD_LINK) -lprotobuf -lboost_thread -lboost_filesystem -lboost_system -lboost_serialization -lthrift -lJerasure -lboost_timer

ALL =	jelly

SRC =	$(shell echo *.cpp gen-cpp/jellyinternal_constants.cpp gen-cpp/JellyInternal.cpp gen-cpp/jellyinternal_types.cpp boost_extension/*.cpp)
OBJ =	$(SRC:.cpp=.o)



all: $(ALL)

JellyInclude.h.gch: JellyInclude.h
	$(CXX) $(CXXFLAGS) JellyInclude.h

clean:
	rm -f core *.o gen-cpp/*.o $(ALL) *.gch

gen-cpp: jellyinternal.thrift
	thrift --gen cpp jellyinternal.thrift

always:
	cp return_codes.h $(MAIDSAFE_DIR)/include/maidsafe/dht/

jelly: always JellyInclude.h.gch gen-cpp $(OBJ)
	$(CXX) $(CFLAGS) -o jelly $(OBJ) $(LDFLAGS)
