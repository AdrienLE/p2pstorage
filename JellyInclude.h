#pragma once

#include "jellutils/pipe_link.h"
#include "jellutils/crypt.h"

#include "maidsafe/common/rsa.h"
#include "maidsafe/common/utils.h"
#include "maidsafe/common/log.h"

#include "thrift/transport/TServerSocket.h"
#include "thrift/transport/TSocket.h"
#include "thrift/protocol/TBinaryProtocol.h"
#include "thrift/transport/TBufferTransports.h"
#include "thrift/concurrency/PosixThreadFactory.h"

extern "C"
{
#include "jerasure/jerasure.h"
#include "jerasure/cauchy.h"
};

#include <boost/lexical_cast.hpp>
#include <boost/format.hpp>
#include <boost/shared_array.hpp>
#include <boost/timer/timer.hpp>
#include <unistd.h>
#include <pwd.h>
#include <exception>
#include <sstream>
#include <fstream>

#include <memory>
#include <string>
#include <vector>

#include "boost/date_time/posix_time/posix_time_types.hpp"
#include "boost/thread/condition_variable.hpp"
#include "boost/thread/mutex.hpp"

#include "maidsafe/dht/config.h"
#include "maidsafe/dht/node-api.h"
#include "maidsafe/dht/node_container.h"

#include "boost/format.hpp"
#include "boost/filesystem.hpp"
#ifdef __MSVC__
#  pragma warning(push)
#  pragma warning(disable: 4127)
#endif
#include "boost/tokenizer.hpp"
#ifdef __MSVC__
#  pragma warning(pop)
#endif
#include "boost/lexical_cast.hpp"
#include "maidsafe/common/crypto.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/common/log.h"
#include "maidsafe/dht/contact.h"
#include "maidsafe/dht/node_id.h"
#include "maidsafe/dht/node-api.h"

#include "thrift/server/TThreadPoolServer.h"
#include "maidsafe/common/utils.h"
#include "maidsafe/common/log.h"
#include "maidsafe/common/crypto.h"

#include <vector>
#include "maidsafe/dht/contact.h"

#include "maidsafe/dht/config.h"
#include "maidsafe/dht/node-api.h"
#include "maidsafe/dht/node_container.h"
#include "maidsafe/common/crypto.h"

#include <signal.h>
#include "boost/filesystem.hpp"
#include "boost/program_options.hpp"

#ifndef __APPLE__
#include "maidsafe/common/breakpad.h"
#endif
#include "maidsafe/common/crypto.h"
#include "maidsafe/common/utils.h"

#ifdef __MSVC__
#  pragma warning(push)
#  pragma warning(disable: 4127 4244 4267)
#endif
#ifdef __MSVC__
#  pragma warning(pop)
#endif
#include "maidsafe/dht/config.h"
#include "maidsafe/dht/contact.h"
#include "maidsafe/dht/node-api.h"
#include "maidsafe/dht/node_container.h"
#include "maidsafe/dht/node_id.h"
#include "maidsafe/dht/return_codes.h"
#include "maidsafe/dht/version.h"

#include "maidsafe/common/log.h"

#include <boost/unordered_map.hpp>
#include <list>
