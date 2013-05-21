/* Copyright (c) 2011 maidsafe.net limited
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


#ifndef MAIDSAFE_DHT_NODE_CONTAINER_H_
#define MAIDSAFE_DHT_NODE_CONTAINER_H_

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "boost/asio/io_service.hpp"
#include "boost/date_time/posix_time/posix_time_duration.hpp"
#include "boost/thread.hpp"

#include "maidsafe/common/asio_service.h"
#include "maidsafe/common/crypto.h"

#include "maidsafe/transport/rudp_transport.h"
#include "maidsafe/transport/tcp_transport.h"
#include "maidsafe/transport/udp_transport.h"
// TODO(Fraser#5#): 2011-08-30 - remove #include utils.h once NAT detection is
//                  implemented.
#include "maidsafe/transport/utils.h"

#include "maidsafe/dht/config.h"
#include "maidsafe/dht/message_handler.h"
#include "maidsafe/dht/version.h"
#include "maidsafe/dht/node-api.h"
#include "maidsafe/dht/return_codes.h"

#if MAIDSAFE_DHT_VERSION != 3200
#  error This API is not compatible with the installed library.\
    Please update the maidsafe-dht library.
#endif

namespace args = std::placeholders;
namespace bptime = boost::posix_time;

namespace maidsafe {

namespace dht {

template <typename NodeType>
class NodeContainer {
 public:
  NodeContainer();
  virtual ~NodeContainer();

  virtual void Init(
      uint8_t thread_count,
      KeyPairPtr key_pair,
      MessageHandlerPtr message_handler,
      bool client_only_node,
      uint16_t k = 8,
      uint16_t alpha = 3,
      uint16_t beta = 2,
      bptime::time_duration mean_refresh_interval = bptime::hours(1));

  // For a non-client, starts listening on a random port within the range.  Then
  // for all types, joins network.
  int Start(const std::vector<Contact> &bootstrap_contacts,
            std::pair<uint16_t, uint16_t> port_range);
  // Joins the network. Only for a client only nodes.
  int StartClient(const std::vector<Contact> &bootstrap_contacts);

  // Stops listening (if non-client) and leaves network.  Joins all threads.
  int Stop(std::vector<Contact> *bootstrap_contacts);

  // These 8 functions call the corresponding function on node_ using the
  // corresponding member callback functors of this class.
  void Join(const NodeId &node_id,
            const std::vector<Contact> &bootstrap_contacts);
  void Store(const Key &key,
             const std::string &value,
             const std::string &signature,
             const boost::posix_time::time_duration &ttl,
             PrivateKeyPtr private_key);
  void Delete(const Key &key,
              const std::string &value,
              const std::string &signature,
              PrivateKeyPtr private_key);
  void Update(const Key &key,
              const std::string &new_value,
              const std::string &new_signature,
              const std::string &old_value,
              const std::string &old_signature,
              const boost::posix_time::time_duration &ttl,
              PrivateKeyPtr private_key);
  void FindValue(const Key &key,
                 PrivateKeyPtr private_key,
                 const uint16_t &extra_contacts = 0);
  void FindNodes(const Key &key,
                 const uint16_t &extra_contacts = 0);
  void GetContact(const NodeId &node_id);
  void Ping(const Contact &contact);

  // These Make<XXX>Functor functions set the appropriate <XXX>_functor_ by
  // binding the corresponding private <XXX>Callback method.
  void MakeJoinFunctor(boost::mutex *mutex,
                       boost::condition_variable *cond_var);
  void MakeStoreFunctor(boost::mutex *mutex,
                        boost::condition_variable *cond_var);
  void MakeDeleteFunctor(boost::mutex *mutex,
                         boost::condition_variable *cond_var);
  void MakeUpdateFunctor(boost::mutex *mutex,
                         boost::condition_variable *cond_var);
  void MakeFindValueFunctor(boost::mutex *mutex,
                            boost::condition_variable *cond_var);
  void MakeFindNodesFunctor(boost::mutex *mutex,
                            boost::condition_variable *cond_var);
  void MakeGetContactFunctor(boost::mutex *mutex,
                             boost::condition_variable *cond_var);
  void MakePingFunctor(boost::mutex *mutex,
                       boost::condition_variable *cond_var);
  // Convenience method for where all callback functors use the same mutex and
  // cond_var
  void MakeAllCallbackFunctors(boost::mutex *mutex,
                               boost::condition_variable *cond_var);

  // These 7 setters allow using a different callback method to the one provided
  // in this class.
  void set_join_functor(const JoinFunctor &functor) {
    join_functor_ = functor;
  }
  void set_store_functor(const StoreFunctor &functor) {
    store_functor_ = functor;
  }
  void set_delete_functor(const DeleteFunctor &functor) {
    delete_functor_ = functor;
  }
  void set_update_functor(const UpdateFunctor &functor) {
    update_functor_ = functor;
  }
  void set_find_value_functor(const FindValueFunctor &functor) {
    find_value_functor_ = functor;
  }
  void set_find_nodes_functor(const FindNodesFunctor &functor) {
    find_nodes_functor_ = functor;
  }
  void set_get_contact_functor(const GetContactFunctor &functor) {
    get_contact_functor_ = functor;
  }
  void set_ping_functor(const PingFunctor &functor) {
    ping_functor_ = functor;
  }

  // These 7 getters also set corresponding class member results to
  // kPendingResult and clear any corresponding result structs/containers ready
  // for subsequent calls.
  void GetAndResetJoinResult(int *result);
  void GetAndResetStoreResult(int *result);
  void GetAndResetDeleteResult(int *result);
  void GetAndResetUpdateResult(int *result);
  void GetAndResetFindNodesResult(int *result,
                                  std::vector<Contact> *closest_nodes);
  void GetAndResetFindValueResult(FindValueReturns *find_value_returns);
  void GetAndResetGetContactResult(int *result, Contact *contact);
  void GetAndResetPingResult(int *result);

  // This returns the io_service by reference!  This is needed by almost any
  // asio object which takes an io_service in its constructor.  Ensure that if
  // this getter is used, this class instance outlives the caller.
  boost::asio::io_service &asio_service() { return asio_service_.service(); }

  // Standard getters
  std::shared_ptr<NodeType> node() const { return node_; }
  KeyPairPtr key_pair() const { return key_pair_; }
  std::vector<Contact> bootstrap_contacts() const {
    return bootstrap_contacts_;
  }
  JoinFunctor join_functor() const { return join_functor_; }
  StoreFunctor store_functor() const { return store_functor_; }
  DeleteFunctor delete_functor() const { return delete_functor_; }
  UpdateFunctor update_functor() const { return update_functor_; }
  FindValueFunctor find_value_functor() const { return find_value_functor_; }
  FindNodesFunctor find_nodes_functor() const { return find_nodes_functor_; }
  GetContactFunctor get_contact_functor() const { return get_contact_functor_; }
  PingFunctor ping_functor() const { return ping_functor_; }

  // These WaitFunctors can be used inside boost wait or timed_wait functions
  // as predicates.
  WaitFunctor wait_for_join_functor() const { return wait_for_join_functor_; }
  WaitFunctor wait_for_store_functor() const { return wait_for_store_functor_; }
  WaitFunctor wait_for_delete_functor() const {
    return wait_for_delete_functor_;
  }
  WaitFunctor wait_for_update_functor() const {
    return wait_for_update_functor_;
  }
  WaitFunctor wait_for_find_value_functor() const {
    return wait_for_find_value_functor_;
  }
  WaitFunctor wait_for_find_nodes_functor() const {
    return wait_for_find_nodes_functor_;
  }
  WaitFunctor wait_for_get_contact_functor() const {
    return wait_for_get_contact_functor_;
  }
  WaitFunctor wait_for_ping_functor() const { return wait_for_ping_functor_; }


 protected:
  AsioService asio_service_;
  TransportPtr listening_transport_;
  MessageHandlerPtr message_handler_;
  KeyPairPtr key_pair_;
  std::shared_ptr<NodeType> node_;
  std::vector<Contact> bootstrap_contacts_;
  int join_result_, store_result_, delete_result_, update_result_,
      find_nodes_result_, get_contact_result_, ping_result_;
  FindValueReturns find_value_returns_;
  std::vector<Contact> find_nodes_closest_nodes_;
  Contact gotten_contact_;
  WaitFunctor wait_for_join_functor_;
  WaitFunctor wait_for_store_functor_;
  WaitFunctor wait_for_delete_functor_;
  WaitFunctor wait_for_update_functor_;
  WaitFunctor wait_for_find_value_functor_;
  WaitFunctor wait_for_find_nodes_functor_;
  WaitFunctor wait_for_get_contact_functor_;
  WaitFunctor wait_for_ping_functor_;

 private:
  NodeContainer(const NodeContainer&);
  NodeContainer &operator=(const NodeContainer&);
  void JoinCallback(int result_in,
                    boost::mutex *mutex,
                    boost::condition_variable *cond_var);
  void StoreCallback(int result_in,
                     boost::mutex *mutex,
                     boost::condition_variable *cond_var);
  void DeleteCallback(int result_in,
                      boost::mutex *mutex,
                      boost::condition_variable *cond_var);
  void UpdateCallback(int result_in,
                      boost::mutex *mutex,
                      boost::condition_variable *cond_var);
  void FindValueCallback(FindValueReturns find_value_returns_in,
                         boost::mutex *mutex,
                         boost::condition_variable *cond_var);
  void FindNodesCallback(int result_in,
                         std::vector<Contact> closest_nodes_in,
                         boost::mutex *mutex,
                         boost::condition_variable *cond_var);
  void GetContactCallback(int result_in,
                          Contact contact_in,
                          boost::mutex *mutex,
                          boost::condition_variable *cond_var);
  void PingCallback(int result_in,
                    boost::mutex *mutex,
                    boost::condition_variable *cond_var);
  bool ResultReady(int *result) { return *result != kPendingResult; }
  JoinFunctor join_functor_;
  StoreFunctor store_functor_;
  DeleteFunctor delete_functor_;
  UpdateFunctor update_functor_;
  FindValueFunctor find_value_functor_;
  FindNodesFunctor find_nodes_functor_;
  GetContactFunctor get_contact_functor_;
  PingFunctor ping_functor_;
};

template <typename NodeType>
std::string DebugId(const NodeContainer<NodeType> &container) {
  return maidsafe::dht::DebugId(container.node()->contact());
}


template<typename NodeType>
NodeContainer<NodeType>::NodeContainer()
    : asio_service_(),
      listening_transport_(),
      message_handler_(),
      key_pair_(),
      node_(),
      bootstrap_contacts_(),
      join_result_(kPendingResult),
      store_result_(kPendingResult),
      delete_result_(kPendingResult),
      update_result_(kPendingResult),
      find_nodes_result_(kPendingResult),
      get_contact_result_(kPendingResult),
      ping_result_(kPendingResult),
      find_value_returns_(),
      find_nodes_closest_nodes_(),
      gotten_contact_(),
      wait_for_join_functor_(),
      wait_for_store_functor_(),
      wait_for_delete_functor_(),
      wait_for_update_functor_(),
      wait_for_find_value_functor_(),
      wait_for_find_nodes_functor_(),
      wait_for_get_contact_functor_(),
      wait_for_ping_functor_(),
      join_functor_(),
      store_functor_(),
      delete_functor_(),
      update_functor_(),
      find_value_functor_(),
      find_nodes_functor_(),
      get_contact_functor_(),
      ping_functor_() {
  wait_for_join_functor_ =
      std::bind(&NodeContainer<NodeType>::ResultReady, this, &join_result_);
  wait_for_store_functor_ =
      std::bind(&NodeContainer<NodeType>::ResultReady, this, &store_result_);
  wait_for_delete_functor_ =
      std::bind(&NodeContainer<NodeType>::ResultReady, this, &delete_result_);
  wait_for_update_functor_ =
      std::bind(&NodeContainer<NodeType>::ResultReady, this, &update_result_);
  wait_for_find_value_functor_ =
      std::bind(&NodeContainer<NodeType>::ResultReady, this,
                &find_value_returns_.return_code);
  wait_for_find_nodes_functor_ =
      std::bind(&NodeContainer<NodeType>::ResultReady, this,
                &find_nodes_result_);
  wait_for_get_contact_functor_ =
      std::bind(&NodeContainer<NodeType>::ResultReady, this,
                &get_contact_result_);
  wait_for_ping_functor_ =
      std::bind(&NodeContainer<NodeType>::ResultReady, this, &ping_result_);
}

template<typename NodeType>
NodeContainer<NodeType>::~NodeContainer() {
  Stop(nullptr);
}

template <typename NodeType>
void NodeContainer<NodeType>::Init(
    uint8_t thread_count,
    KeyPairPtr key_pair,
    MessageHandlerPtr message_handler,
    bool client_only_node,
    uint16_t k,
    uint16_t alpha,
    uint16_t beta,
    bptime::time_duration mean_refresh_interval) {
  // Create worker threads for asynchronous operations.
  asio_service_.Start(thread_count);

  // Set up private_key if it wasn't passed in - make signing_key_id compatible
  // with type NodeId so that the node's ID can be set as the public key's ID
  if (key_pair) {
    key_pair_ = key_pair;
  } else {
    key_pair_ = KeyPairPtr(new asymm::Keys);
    asymm::GenerateKeyPair(key_pair_.get());
    key_pair_->identity = RandomString(crypto::SHA512::DIGESTSIZE);
  }

  if (message_handler) {
    message_handler_ = message_handler;
  } else {
    PrivateKeyPtr priv_key = PrivateKeyPtr(
        new asymm::PrivateKey(key_pair_->private_key));
    message_handler_.reset(new MessageHandler(priv_key));
  }

  // If this is not a client node, connect message handler to transport for
  // incoming raw messages.  Don't need to connect to on_error() as service
  // doesn't care if reply succeeds or not.
  if (!client_only_node) {
//    listening_transport_.reset(
//        new transport::TcpTransport(asio_service_.service()));
    listening_transport_.reset(
        new transport::TcpTransport(asio_service_.service()));
    listening_transport_->on_message_received()->connect(
        transport::OnMessageReceived::element_type::slot_type(
            &MessageHandler::OnMessageReceived, message_handler_.get(),
            _1, _2, _3, _4).track_foreign(message_handler_));
    listening_transport_->on_error()->connect(
        transport::OnError::element_type::slot_type(
            &MessageHandler::OnError, message_handler_.get(),
            _1, _2).track_foreign(message_handler));
  }

  // Create node
  node_.reset(new NodeType(asio_service_.service(), listening_transport_,
                           message_handler_, key_pair_, client_only_node, k,
                           alpha, beta, mean_refresh_interval));
}

template <typename NodeType>
int NodeContainer<NodeType>::Start(
    const std::vector<dht::Contact> &bootstrap_contacts,
    std::pair<uint16_t, uint16_t> port_range) {
  bootstrap_contacts_ = bootstrap_contacts;
  int result(kPendingResult);
  if (!node_->client_only_node()) {
     // Workaround until NAT detection is up.
    std::vector<transport::IP> ips = transport::GetLocalAddresses();
    transport::Endpoint endpoint(
        ips.empty() ? IP::from_string("127.0.0.1") : ips.front(), 0);
    int result(transport::kError);
    std::vector<Port> try_ports;
    if (port_range.first == port_range.second) {
      try_ports.reserve(1);
      try_ports.push_back(port_range.first);
    } else  {
      if (port_range.first > port_range.second)
        port_range = std::make_pair(port_range.second, port_range.first);
      try_ports.reserve(port_range.second - port_range.first);
      for (Port port(port_range.first); port != port_range.second; ++port)
        try_ports.push_back(port);
      std::random_shuffle(try_ports.begin(), try_ports.end());
    }
    for (auto itr(try_ports.begin()); itr != try_ports.end(); ++itr) {
      endpoint.port = *itr;
      result = listening_transport_->StartListening(endpoint);
      if (transport::kSuccess == result) {
        break;
      } else {
        listening_transport_->StopListening();
      }
    }
    if (transport::kSuccess != result) {
      return result;
    }
  }

  boost::mutex mutex;
  boost::condition_variable cond_var;
  NodeId node_id(key_pair_->identity);
  JoinFunctor join_functor(std::bind(&NodeContainer<NodeType>::JoinCallback,
                           this, args::_1, &mutex, &cond_var));

  boost::function<bool()> wait_functor = boost::bind(
      &NodeContainer<NodeType>::ResultReady, this, &join_result_);
  boost::mutex::scoped_lock lock(mutex);
  node_->Join(node_id, bootstrap_contacts_, join_functor);
  bool wait_success(cond_var.timed_wait(lock, bptime::minutes(1),
                                        wait_functor));
  result = kPendingResult;
  GetAndResetJoinResult(&result);
  return (wait_success ? result : kTimedOut);
}

template <typename NodeType>
int NodeContainer<NodeType>::StartClient(
    const std::vector<dht::Contact> &bootstrap_contacts) {
  if (node_->client_only_node()) {
    std::pair<Port, Port> port_range(0, 0);
    return Start(bootstrap_contacts, port_range);
  }
  return kGeneralError;
}

template <typename NodeType>
int NodeContainer<NodeType>::Stop(std::vector<Contact> *bootstrap_contacts) {
  try {
    if (node_->joined()) {
      node_->Leave(&bootstrap_contacts_);
      if (bootstrap_contacts)
        *bootstrap_contacts = bootstrap_contacts_;
    }
  } catch(const std::exception&) {
    return kGeneralError;
  }
  if (listening_transport_)
    listening_transport_->StopListening();
  asio_service_.Stop();
  return kSuccess;
}

template <typename NodeType>
void NodeContainer<NodeType>::Join(
    const NodeId &node_id,
    const std::vector<Contact> &bootstrap_contacts) {
  node_->Join(node_id, bootstrap_contacts, join_functor_);
}

template <typename NodeType>
void NodeContainer<NodeType>::Store(const Key &key,
                                    const std::string &value,
                                    const std::string &signature,
                                    const boost::posix_time::time_duration &ttl,
                                    PrivateKeyPtr private_key) {
  node_->Store(key, value, signature, ttl, private_key, store_functor_);
}

template <typename NodeType>
void NodeContainer<NodeType>::Delete(const Key &key,
                                     const std::string &value,
                                     const std::string &signature,
                                     PrivateKeyPtr private_key) {
  node_->Delete(key, value, signature, private_key, delete_functor_);
}

template <typename NodeType>
void NodeContainer<NodeType>::Update(
    const Key &key,
    const std::string &new_value,
    const std::string &new_signature,
    const std::string &old_value,
    const std::string &old_signature,
    const boost::posix_time::time_duration &ttl,
    PrivateKeyPtr private_key) {
  node_->Update(key, new_value, new_signature, old_value, old_signature, ttl,
                private_key, update_functor_);
}

template <typename NodeType>
void NodeContainer<NodeType>::FindValue(const Key &key,
                                        PrivateKeyPtr private_key,
                                        const uint16_t &extra_contacts) {
  node_->FindValue(key, private_key, find_value_functor_, extra_contacts);
}

template <typename NodeType>
void NodeContainer<NodeType>::FindNodes(const Key &key,
                                        const uint16_t &extra_contacts) {
  node_->FindNodes(key, find_nodes_functor_, extra_contacts);
}

template <typename NodeType>
void NodeContainer<NodeType>::GetContact(const NodeId &node_id) {
  node_->GetContact(node_id, get_contact_functor_);
}

template <typename NodeType>
void NodeContainer<NodeType>::Ping(const Contact &contact) {
  node_->Ping(contact, ping_functor_);
}

template <typename NodeType>
void NodeContainer<NodeType>::JoinCallback(
    int result_in,
    boost::mutex *mutex,
    boost::condition_variable *cond_var) {
  boost::mutex::scoped_lock lock(*mutex);
  join_result_ = result_in;
  cond_var->notify_one();
}

template <typename NodeType>
void NodeContainer<NodeType>::StoreCallback(
    int result_in,
    boost::mutex *mutex,
    boost::condition_variable *cond_var) {
  boost::mutex::scoped_lock lock(*mutex);
  store_result_ = result_in;
  cond_var->notify_one();
}

template <typename NodeType>
void NodeContainer<NodeType>::DeleteCallback(
    int result_in,
    boost::mutex *mutex,
    boost::condition_variable *cond_var) {
  boost::mutex::scoped_lock lock(*mutex);
  delete_result_ = result_in;
  cond_var->notify_one();
}

template <typename NodeType>
void NodeContainer<NodeType>::UpdateCallback(
    int result_in,
    boost::mutex *mutex,
    boost::condition_variable *cond_var) {
  boost::mutex::scoped_lock lock(*mutex);
  update_result_ = result_in;
  cond_var->notify_one();
}

template <typename NodeType>
void NodeContainer<NodeType>::FindValueCallback(
    FindValueReturns find_value_returns_in,
    boost::mutex *mutex,
    boost::condition_variable *cond_var) {
  boost::mutex::scoped_lock lock(*mutex);
  find_value_returns_ = find_value_returns_in;
  cond_var->notify_one();
}

template <typename NodeType>
void NodeContainer<NodeType>::FindNodesCallback(
    int result_in,
    std::vector<Contact> closest_nodes_in,
    boost::mutex *mutex,
    boost::condition_variable *cond_var) {
  boost::mutex::scoped_lock lock(*mutex);
  find_nodes_result_ = result_in;
  find_nodes_closest_nodes_ = closest_nodes_in;
  cond_var->notify_one();
}

template <typename NodeType>
void NodeContainer<NodeType>::GetContactCallback(
    int result_in,
    Contact contact_in,
    boost::mutex *mutex,
    boost::condition_variable *cond_var) {
  boost::mutex::scoped_lock lock(*mutex);
  get_contact_result_ = result_in;
  gotten_contact_ = contact_in;
  cond_var->notify_one();
}

template <typename NodeType>
void NodeContainer<NodeType>::PingCallback(
    int result_in,
    boost::mutex *mutex,
    boost::condition_variable *cond_var) {
  boost::mutex::scoped_lock lock(*mutex);
  ping_result_ = result_in;
  cond_var->notify_one();
}

template <typename NodeType>
void NodeContainer<NodeType>::MakeJoinFunctor(
    boost::mutex *mutex,
    boost::condition_variable *cond_var) {
  join_functor_ = std::bind(&NodeContainer<NodeType>::JoinCallback, this,
                            args::_1, mutex, cond_var);
}

template <typename NodeType>
void NodeContainer<NodeType>::MakeStoreFunctor(
    boost::mutex *mutex,
    boost::condition_variable *cond_var) {
  store_functor_ = std::bind(&NodeContainer<NodeType>::StoreCallback, this,
                             args::_1, mutex, cond_var);
}

template <typename NodeType>
void NodeContainer<NodeType>::MakeDeleteFunctor(
    boost::mutex *mutex,
    boost::condition_variable *cond_var) {
  delete_functor_ = std::bind(&NodeContainer<NodeType>::DeleteCallback, this,
                              args::_1, mutex, cond_var);
}

template <typename NodeType>
void NodeContainer<NodeType>::MakeUpdateFunctor(
    boost::mutex *mutex,
    boost::condition_variable *cond_var) {
  update_functor_ = std::bind(&NodeContainer<NodeType>::UpdateCallback, this,
                              args::_1, mutex, cond_var);
}

template <typename NodeType>
void NodeContainer<NodeType>::MakeFindValueFunctor(
    boost::mutex *mutex,
    boost::condition_variable *cond_var) {
  find_value_functor_ = std::bind(&NodeContainer<NodeType>::FindValueCallback,
                                  this, args::_1, mutex, cond_var);
}

template <typename NodeType>
void NodeContainer<NodeType>::MakeFindNodesFunctor(
    boost::mutex *mutex,
    boost::condition_variable *cond_var) {
  find_nodes_functor_ = std::bind(&NodeContainer<NodeType>::FindNodesCallback,
                                  this, args::_1, args::_2, mutex, cond_var);
}

template <typename NodeType>
void NodeContainer<NodeType>::MakeGetContactFunctor(
    boost::mutex *mutex,
    boost::condition_variable *cond_var) {
  get_contact_functor_ = std::bind(&NodeContainer<NodeType>::GetContactCallback,
                                   this, args::_1, args::_2, mutex, cond_var);
}

template <typename NodeType>
void NodeContainer<NodeType>::MakePingFunctor(
    boost::mutex *mutex,
    boost::condition_variable *cond_var) {
  ping_functor_ = std::bind(&NodeContainer<NodeType>::PingCallback, this,
                            args::_1, mutex, cond_var);
}

template <typename NodeType>
void NodeContainer<NodeType>::MakeAllCallbackFunctors(
    boost::mutex *mutex,
    boost::condition_variable *cond_var) {
  MakeJoinFunctor(mutex, cond_var);
  MakeStoreFunctor(mutex, cond_var);
  MakeDeleteFunctor(mutex, cond_var);
  MakeUpdateFunctor(mutex, cond_var);
  MakeFindValueFunctor(mutex, cond_var);
  MakeFindNodesFunctor(mutex, cond_var);
  MakeGetContactFunctor(mutex, cond_var);
  MakePingFunctor(mutex, cond_var);
}


template <typename NodeType>
void NodeContainer<NodeType>::GetAndResetJoinResult(int *result) {
  if (result)
    *result = join_result_;
  join_result_ = kPendingResult;
}

template <typename NodeType>
void NodeContainer<NodeType>::GetAndResetStoreResult(int *result) {
  if (result)
    *result = store_result_;
  store_result_ = kPendingResult;
}

template <typename NodeType>
void NodeContainer<NodeType>::GetAndResetDeleteResult(int *result) {
  if (result)
    *result = delete_result_;
  delete_result_ = kPendingResult;
}

template <typename NodeType>
void NodeContainer<NodeType>::GetAndResetUpdateResult(int *result) {
  if (result)
    *result = update_result_;
  update_result_ = kPendingResult;
}

template <typename NodeType>
void NodeContainer<NodeType>::GetAndResetFindNodesResult(
    int *result,
    std::vector<Contact> *closest_nodes) {
  if (result)
    *result = find_nodes_result_;
  if (closest_nodes)
    *closest_nodes = find_nodes_closest_nodes_;
  find_nodes_result_ = kPendingResult;
  find_nodes_closest_nodes_.clear();
}

template <typename NodeType>
void NodeContainer<NodeType>::GetAndResetFindValueResult(
    FindValueReturns *find_value_returns) {
  if (find_value_returns)
    *find_value_returns = find_value_returns_;
  find_value_returns_.cached_copy_holder = Contact();
  find_value_returns_.closest_nodes.clear();
  find_value_returns_.needs_cache_copy = Contact();
  find_value_returns_.return_code = kPendingResult;
  find_value_returns_.values_and_signatures.clear();
}

template <typename NodeType>
void NodeContainer<NodeType>::GetAndResetGetContactResult(int *result,
                                                          Contact *contact) {
  if (result)
    *result = get_contact_result_;
  if (contact)
    *contact = gotten_contact_;
  get_contact_result_ = kPendingResult;
  gotten_contact_ = Contact();
}

template <typename NodeType>
void NodeContainer<NodeType>::GetAndResetPingResult(int *result) {
  if (result)
    *result = ping_result_;
  ping_result_ = kPendingResult;
}

}  // namespace dht

}  // namespace maidsafe

#endif  // MAIDSAFE_DHT_NODE_CONTAINER_H_
