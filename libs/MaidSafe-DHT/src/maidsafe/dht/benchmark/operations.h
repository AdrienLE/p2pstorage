/* Copyright (c) 2010 maidsafe.net limited
All rights reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

    * Redistributions of source code must retain the above copyright notice,
    this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright notice,
    this list of conditions and the following disclaimer in the documentation
    and/or other materials provided with the distribution.
    * Neither the name of the maidsafe.net limited nor the names of its
    contributors may be used to endorse or promote products derived from this
    software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#ifndef MAIDSAFE_DHT_BENCHMARK_OPERATIONS_H_
#define MAIDSAFE_DHT_BENCHMARK_OPERATIONS_H_

#include <map>
#include <string>
#include <vector>
#include "boost/thread/condition_variable.hpp"
#include "boost/thread/locks.hpp"
#include "maidsafe/common/crypto.h"
#include "maidsafe/common/utils.h"
#include "maidsafe/dht/contact.h"

namespace maidsafe {

namespace dht {

namespace rpcprotocol {
typedef std::map<std::string, Stats<uint64_t>> RpcStatsMap;
}  // namespace rpcprotocol

class Node;
class NodeId;

namespace benchmark {

struct CallbackData {
  CallbackData() : returned_count(), succeeded_count(), content(), mutex(),
                   condition() {}
  int returned_count, succeeded_count;
  std::string content;
  boost::mutex mutex;
  boost::condition_variable condition;
};

class Operations {
 public:
  explicit Operations(std::shared_ptr<Node> node);
  void TestFindAndPing(const std::vector<NodeId> &nodes,
                       const int &iterations);
  void TestStoreAndFind(const std::vector<NodeId> &nodes,
                        const int &iterations, const bool &sign);
  static NodeId GetModId(int iteration);
  static void PrintRpcTimings(const rpcprotocol::RpcStatsMap &rpc_timings);
 private:
  void PingCallback(const std::string &result,
                    std::shared_ptr<CallbackData> data);
  void GetNodeContactDetailsCallback(const std::string &result,
                                     std::shared_ptr<CallbackData> data);
  void StoreCallback(const std::string &result,
                     std::shared_ptr<CallbackData> data);
  void FindValueCallback(const std::string &result,
                         std::shared_ptr<CallbackData> data);
  std::shared_ptr<Node> node_;
//  crypto::Crypto cryobj_;
  std::string public_key_validation_;
  asymm::PublicKey public_key_;
  asymm::PrivateKey private_key_;
};

}  // namespace benchmark

}  // namespace dht

}  // namespace maidsafe

#endif  // MAIDSAFE_DHT_BENCHMARK_OPERATIONS_H_
