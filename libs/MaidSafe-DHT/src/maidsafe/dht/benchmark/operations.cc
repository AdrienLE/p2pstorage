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

#include "maidsafe/dht/benchmark/operations.h"

#include <cassert>
#include <iomanip>
#include <iostream>  // NOLINT
#include <string>
#include <vector>

#include "boost/format.hpp"
#include "boost/filesystem.hpp"
#include "boost/filesystem/fstream.hpp"
#include "boost/thread.hpp"
#include "boost/tokenizer.hpp"
#include "boost/lexical_cast.hpp"

#include "maidsafe/dht/log.h"
#include "maidsafe/dht/node_id.h"
#include "maidsafe/dht/node-api.h"


namespace maidsafe {

namespace dht {

namespace benchmark {

Operations::Operations(std::shared_ptr<Node> node)
    : node_(node),
      public_key_validation_(),
      public_key_(),
      private_key_() {
//  cryobj_.set_symm_algorithm(crypto::AES_256);
//  cryobj_.set_hash_algorithm(crypto::SHA_512);
  asymm::Keys kp;
  asymm::GenerateKeyPair(&kp);
  public_key_ = kp.public_key;
  private_key_ = kp.private_key;
}

void Operations::TestFindAndPing(const std::vector<NodeId> &nodes,
                                 const int &iterations) {
  std::vector<Contact> contacts;
  {
    printf("Finding %d nodes...\n", nodes.size());

    Stats<uint64_t> stats;
    std::shared_ptr<CallbackData> data(new CallbackData());
    boost::mutex::scoped_lock lock(data->mutex);
    for (size_t i = 0; i < nodes.size(); ++i) {
//     uint64_t t = GetEpochMilliseconds();
//      node_->GetNodeContactDetails(
//            nodes[i],
//            boost::bind(&Operations::GetNodeContactDetailsCallback, this, _1,
//                        data),
//            false);
//      while (static_cast<size_t>(data->returned_count) <= i)
//        data->condition.wait(lock);
//      stats.Add(GetEpochMilliseconds() - t);
      Contact ctc;
//      ctc.ParseFromString(data->content);
      contacts.push_back(ctc);
    }

    printf("Done: total %.2f s, min/avg/max %.2f/%.2f/%.2f s\n",
            stats.Sum() / 1000.0,
            stats.Min() / 1000.0,
            stats.Mean() / 1000.0,
            stats.Max() / 1000.0);
  }
  if (!contacts.empty()) {
    printf("Pinging %d contacts, %d iterations...\n",
           contacts.size(), iterations);

    Stats<uint64_t> stats;
    for (size_t i = 0; i < contacts.size(); ++i) {
      Stats<uint64_t> it_stats;
      std::shared_ptr<CallbackData> data(new CallbackData());
      boost::mutex::scoped_lock lock(data->mutex);
      for (int j = 0; j < iterations; ++j) {
//        uint64_t t = GetEpochMilliseconds();
//        node_->Ping(contacts[i], boost::bind(
//            &Operations::PingCallback, this, _1, data));
        while (data->returned_count <= j)
          data->condition.wait(lock);
//        it_stats.Add(GetEpochMilliseconds() - t);
      }
      stats.Add(it_stats.Mean());
      printf(" Pinged contact %d, %02d/%02d times "
             "(total %.2f s, min/avg/max %.2f/%.2f/%.2f s)\n", i + 1,
             data->succeeded_count, data->returned_count,
             it_stats.Sum() / 1000.0,
             it_stats.Min() / 1000.0,
             it_stats.Mean() / 1000.0,
             it_stats.Max() / 1000.0);
    }

    printf("Done: min/avg/max %.2f/%.2f/%.2f s\n",
            stats.Min() / 1000.0,
            stats.Mean() / 1000.0,
            stats.Max() / 1000.0);
  } else {
    printf("No contacts for nodes found.\n");
  }
}

void Operations::TestStoreAndFind(const std::vector<NodeId> &nodes,
                                  const int &iterations, const bool &/*sign*/) {
  for (int val = 0; val < 4; ++val) {
    std::string size, value;
    switch (val) {
      case 0:
        value = RandomString(1 << 4);
        size = "16 byte";
        break;
      case 1:
        value = RandomString(1 << 10);
        size = "1 KB";
        break;
      case 2:
        value = RandomString(1 << 17);
        size = "128 KB";
        break;
      case 3:
        value = RandomString(1 << 20);
        size = "1 MB";
        break;
    }
    printf("Storing %s value on %d * k closest nodes, %d iterations...\n",
           size.c_str(), nodes.size(), iterations);


    Stats<uint64_t> store_stats;
    for (size_t i = 0; i < nodes.size(); ++i) {
      Stats<uint64_t> it_stats;
      std::shared_ptr<CallbackData> data(new CallbackData());
      boost::mutex::scoped_lock lock(data->mutex);
//      for (int j = 0; j < iterations; ++j) {
//        NodeId mod =
//            GetModId(val * iterations * nodes.size() + i * iterations + j);
//        NodeId key(nodes[i] ^ mod);
//        protobuf::SignedValue sig_val;
//        protobuf::MessageSignature sig_req;
//        if (sign) {
//          std::string req_sig, ser_sig_val;
//
//
//  Validifier signer;
//
//
//          sig_val.set_value(value);
// //          sig_val.set_value_signature(cryobj_.AsymSign(value, "",
// //              private_key_, crypto::STRING_STRING));
// //          ser_sig_val = sig_val.SerializeAsString();
// //          sig_req.set_signer_id(node_->node_id().String());
// //          sig_req.set_public_key(public_key_);
// //          sig_req.set_public_key_validation(public_key_validation_);
// //          sig_req.set_request_signature(req_sig);
//        }
//        uint64_t t = GetEpochMilliseconds();
//        if (sign) {
//          node_->StoreValue(key, sig_val, sig_req, 86400, boost::bind(
//              &Operations::StoreCallback, this, _1, data));
//        } else {
//          node_->StoreValue(key, value, 86400, boost::bind(
//              &Operations::StoreCallback, this, _1, data));
//        }
//        while (data->returned_count <= j)
//          data->condition.wait(lock);
//        it_stats.Add(GetEpochMilliseconds() - t);
//      }
//      store_stats.Add(it_stats.Mean());
//      printf(" Stored close to %d, %02d/%02d times "
//             "(total %.2f s, min/avg/max %.2f/%.2f/%.2f s)\n", i + 1,
//             data->succeeded_count, data->returned_count,
//             it_stats.Sum() / 1000.0,
//             it_stats.Min() / 1000.0,
//             it_stats.Mean() / 1000.0,
//             it_stats.Max() / 1000.0);
    }

    printf("Done: min/avg/max %.2f/%.2f/%.2f s\n",
           store_stats.Min() / 1000.0,
           store_stats.Mean() / 1000.0,
           store_stats.Max() / 1000.0);

    printf("Loading %s value from %d closest nodes, %d iterations...\n",
           size.c_str(), nodes.size(), iterations);

    Stats<uint64_t> load_stats;
    for (size_t i = 0; i < nodes.size(); ++i) {
      Stats<uint64_t> it_stats;
      std::shared_ptr<CallbackData> data(new CallbackData());
      boost::mutex::scoped_lock lock(data->mutex);
      for (int j = 0; j < iterations; ++j) {
        NodeId mod =
            GetModId(val * iterations * static_cast<int>(nodes.size() + i) *
                     iterations + j);
//        uint64_t t = GetEpochMilliseconds();
//        node_->FindValue(nodes[i] ^ mod, false, boost::bind(
//            &Operations::FindValueCallback, this, _1, data));
        while (data->returned_count <= j)
          data->condition.wait(lock);
//        it_stats.Add(GetEpochMilliseconds() - t);
      }
      load_stats.Add(it_stats.Mean());
      printf(" Loaded from %d, %02d/%02d times "
             "(total %.2f s, min/avg/max %.2f/%.2f/%.2f s)\n", i + 1,
             data->succeeded_count, data->returned_count,
             it_stats.Sum() / 1000.0,
             it_stats.Min() / 1000.0,
             it_stats.Mean() / 1000.0,
             it_stats.Max() / 1000.0);
    }

    printf("Done: min/avg/max %.2f/%.2f/%.2f s\n",
           load_stats.Min() / 1000.0,
           load_stats.Mean() / 1000.0,
           load_stats.Max() / 1000.0);
  }
}


void Operations::PingCallback(const std::string &/*result*/,
                              std::shared_ptr<CallbackData> data) {
  boost::mutex::scoped_lock lock(data->mutex);
  data->content.clear();
  ++data->returned_count;
//  PingResponse msg;
//  if (msg.ParseFromString(result) && msg.result())
//    ++data->succeeded_count;
  data->condition.notify_one();
}

void Operations::GetNodeContactDetailsCallback(const std::string &/*result*/,
                                  std::shared_ptr<CallbackData> data) {
  boost::mutex::scoped_lock lock(data->mutex);
  data->content.clear();
  ++data->returned_count;
//  FindNodeResult msg;
//  if (msg.ParseFromString(result) && msg.result()) {
//    ++data->succeeded_count;
//    data->content = msg.contact();
//  }
  data->condition.notify_one();
}

void Operations::StoreCallback(const std::string &/*result*/,
                               std::shared_ptr<CallbackData> data) {
  boost::mutex::scoped_lock lock(data->mutex);
  data->content.clear();
  ++data->returned_count;
//  StoreResponse msg;
//  if (msg.ParseFromString(result) && msg.result())
//    ++data->succeeded_count;
  data->condition.notify_one();
}

void Operations::FindValueCallback(const std::string &/*result*/,
                                   std::shared_ptr<CallbackData> data) {
  boost::mutex::scoped_lock lock(data->mutex);
  data->content.clear();
  ++data->returned_count;
//  FindResponse msg;
//  if (msg.ParseFromString(result) && msg.result() &&
//      (msg.values_size() > 0 || msg.signed_values_size() > 0))
//    ++data->succeeded_count;
  data->condition.notify_one();
}

/**
 * Calculates a Kademlia ID with smallest possible distance from 000..000,
 * with a unique value for each (positive) iteration number.
 */
NodeId Operations::GetModId(int iteration) {
  uint16_t bits = kKeySizeBits - 1;
  NodeId id;
  while (iteration > bits) {
    id = id ^ NodeId(bits);
    iteration -= (bits + 1);
    --bits;
  }
  return id ^ NodeId(static_cast<uint16_t>(iteration));
}

void Operations::PrintRpcTimings(const rpcprotocol::RpcStatsMap &rpc_timings) {
  DLOG(INFO) << boost::format("Calls  RPC Name  %40t% min/avg/max\n");
  for (rpcprotocol::RpcStatsMap::const_iterator it = rpc_timings.begin();
       it != rpc_timings.end();
       ++it) {
    DLOG(INFO) << boost::format("%1% : %2% %40t% %3% / %4% / %5% \n")
           % it->second.Size()
           % it->first.c_str()
           % it->second.Min()  // / 1000.0
           % it->second.Mean()  // / 1000.0
           % it->second.Max();  // / 1000.0;
  }
}

}  // namespace benchmark

}  // namespace dht

}  // namespace maidsafe
