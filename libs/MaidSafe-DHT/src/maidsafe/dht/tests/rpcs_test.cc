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
#include <bitset>
#include <memory>

#include "boost/lexical_cast.hpp"
#include "boost/thread/mutex.hpp"
#include "boost/thread.hpp"
#include "boost/asio/io_service.hpp"
#include "boost/enable_shared_from_this.hpp"

#include "maidsafe/common/asio_service.h"
#include "maidsafe/common/test.h"
#include "maidsafe/common/crypto.h"
#include "maidsafe/common/utils.h"
#include "maidsafe/transport/rudp_transport.h"
#include "maidsafe/transport/tcp_transport.h"
#include "maidsafe/transport/udp_transport.h"
#include "maidsafe/dht/config.h"
#ifdef __MSVC__
#  pragma warning(push)
#  pragma warning(disable: 4127 4244 4267)
#endif
#include "maidsafe/dht/rpcs.pb.h"
#ifdef __MSVC__
#  pragma warning(pop)
#endif
#include "maidsafe/dht/utils.h"
#include "maidsafe/dht/service.h"
#include "maidsafe/dht/rpcs.h"
#include "maidsafe/dht/node_id.h"
#include "maidsafe/dht/routing_table.h"
#include "maidsafe/dht/return_codes.h"
#include "maidsafe/dht/message_handler.h"
#include "maidsafe/dht/tests/test_utils.h"

namespace args = std::placeholders;

namespace maidsafe {

namespace dht {

namespace test {

namespace {
const uint16_t g_kKademliaK = 16;
const int g_kRpcClientNo = 5;
const int g_kRpcServersNo = 5;
}  // unnamed namespace

void TestCallback(RankInfoPtr,
                  int callback_code,
                  bool *done,
                  int *response_code) {
  *response_code = callback_code;
  *done = true;
}

void TestFindNodesCallback(RankInfoPtr,
                           int callback_code,
                           std::vector<Contact> contacts,
                           std::vector<Contact> *contact_list,
                           bool *done,
                           int *response_code) {
  *response_code = callback_code;
  *contact_list = contacts;
  *done = true;
}

void TestFindValueCallback(
    RankInfoPtr,
    int callback_code,
    std::vector<ValueAndSignature> values_and_signatures,
    std::vector<Contact> contacts,
    Contact/* cached_copy_holder */,
    std::vector<ValueAndSignature> *return_values_and_signatures,
    std::vector<Contact> *return_contacts,
    bool *done,
    int *response_code) {
  *response_code = callback_code;
  *return_values_and_signatures = values_and_signatures;
  *return_contacts = contacts;
  *done = true;
}

template <typename T>
class RpcsTest : public CreateContactAndNodeId, public testing::Test {
 public:
  RpcsTest()
      : CreateContactAndNodeId(g_kKademliaK),
        node_id_(NodeId::kRandomId),
        routing_table_(new RoutingTable(node_id_, g_kKademliaK)),
        data_store_(new DataStore(bptime::seconds(3600))),
        asio_service_(),
        local_asio_(),
        rank_info_(),
        contacts_(),
        transport_(),
        handler_() {
    asio_service_.Start(3);
    local_asio_.Start(3);
  }

  static void SetUpTestCase() {
    asymm::GenerateKeyPair(&sender_crypto_key_id_);
    asymm::GenerateKeyPair(&receiver_crypto_key_id_);
  }

  PrivateKeyPtr GetPrivateKeyPtr(KeyPairPtr key_pair) {
    return PrivateKeyPtr(new asymm::PrivateKey(key_pair->private_key));
  }

  virtual void SetUp() {
    // rpcs setup
    NodeId rpcs_node_id = GenerateRandomId(node_id_, 502);
    asymm::Keys key_pair;
    key_pair.identity = rpcs_node_id.String();
    key_pair.private_key = sender_crypto_key_id_.private_key;
    key_pair.public_key = sender_crypto_key_id_.public_key;
    rpcs_key_pair_.reset(new asymm::Keys(key_pair));
    rpcs_= std::shared_ptr<Rpcs<T>>(new Rpcs<T>( // NOLINT (Fraser)
        asio_service_.service(),
        GetPrivateKeyPtr(rpcs_key_pair_)));
    rpcs_contact_ = ComposeContactWithKey(rpcs_node_id,
                                          5010,
                                          sender_crypto_key_id_);
    rpcs_->set_contact(rpcs_contact_);
    // service setup
    int start_listening_result(transport::kError), attempts(0);
    transport_.reset(new T(local_asio_.service()));
    while (start_listening_result != kSuccess && attempts != 5) {
      Port port((RandomUint32() % 64511) + 1025);
      start_listening_result =
          transport_->StartListening(transport::Endpoint("127.0.0.1", port));
      ++attempts;
    }
    ASSERT_EQ(start_listening_result, kSuccess);
    data_store_->set_debug_id(DebugId(node_id_));
    /* TODO(Viv) Check if this even does anything
    service_key_pair_ = std::shared_ptr<Securifier>(
        new SecurifierGetPublicKeyAndValidation("",
                receiver_crypto_key_id_.public_key,
                    receiver_crypto_key_id_.private_key));*/
    asymm::Keys service_key_pair;
    service_key_pair.public_key = receiver_crypto_key_id_.public_key;
    service_key_pair.private_key = receiver_crypto_key_id_.private_key;
    service_key_pair_.reset(new asymm::Keys(service_key_pair));
    NodeId service_node_id = GenerateRandomId(node_id_, 503);
    service_contact_ = ComposeContactWithKey(service_node_id,
                                             transport_->listening_port(),
                                             receiver_crypto_key_id_);
    service_ = std::shared_ptr<Service>(new Service(
        routing_table_,
        data_store_,
        GetPrivateKeyPtr(service_key_pair_),
        g_kKademliaK));
    service_->set_node_joined(true);
    service_->set_node_contact(service_contact_);
    handler_.reset(new MessageHandler(GetPrivateKeyPtr(service_key_pair_)));
    service_->ConnectToSignals(handler_);
    transport_->on_message_received()->connect(
        transport::OnMessageReceived::element_type::slot_type(
            &MessageHandler::OnMessageReceived, handler_.get(),
            _1, _2, _3, _4).track_foreign(handler_));
  }

  virtual void TearDown() {}

  ~RpcsTest() {
    asio_service_.Stop();
    local_asio_.Stop();
  }

  void PopulateRoutingTable(uint16_t count) {
    std::vector<Contact> rt_contacts;
    while (rt_contacts.size() < count) {
      NodeId contact_id(NodeId::kRandomId);
      Contact contact = ComposeContact(contact_id, 5000);
      AddContact(routing_table_, contact, rank_info_);
      contacts_.push_back(contact);
      routing_table_->GetAllContacts(&rt_contacts);
    }
  }

  void AddToReceiverDataStore(const KeyValueSignature& kvs,
                              const asymm::Keys& crypto_key_data,
                              const Contact& contact,
                              RequestAndSignature& request_signature) {
    protobuf::StoreRequest store_request = MakeStoreRequest(contact, kvs);
    std::string store_message = store_request.SerializeAsString();
    std::string store_message_sig;
    asymm::Sign(store_message, crypto_key_data.private_key, &store_message_sig);
    bptime::time_duration ttl(bptime::pos_infin);
    request_signature = std::make_pair(store_message, store_message_sig);
    EXPECT_EQ(kSuccess, data_store_->StoreValue(kvs, ttl, request_signature,
                                                false));
  }

  void DeleteFromReceiverDataStore(const KeyValueSignature& kvs,
                                   const asymm::Keys& crypto_key_data,
                                   const Contact& contact,
                                   RequestAndSignature& request_signature) {
    protobuf::DeleteRequest delete_request = MakeDeleteRequest(contact, kvs);
    std::string delete_message = delete_request.SerializeAsString();
    std::string delete_message_sig;
    asymm::Sign(delete_message, crypto_key_data.private_key,
               &delete_message_sig);
    request_signature = std::make_pair(delete_message, delete_message_sig);
    EXPECT_TRUE(data_store_->DeleteValue(kvs, request_signature, false));
  }
  // Checks for not deleted value which are not marked as deleted
  bool IsKeyValueInDataStore(KeyValueSignature kvs,
                             std::shared_ptr<DataStore> data_store) {
    std::vector<ValueAndSignature> values_and_signatures;
    data_store->GetValues(kvs.key, &values_and_signatures);
    for (size_t i = 0; i < values_and_signatures.size(); ++i) {
      if ((values_and_signatures[i].first == kvs.value) &&
          (values_and_signatures[i].second == kvs.signature)) {
        return true;
      }
    }
    return false;
  }

  bptime::ptime GetRefreshTime(KeyValueSignature kvs) {
    KeyValueIndex::index<TagKeyValue>::type& index_by_key_value =
        data_store_->key_value_index_->get<TagKeyValue>();
    auto it = index_by_key_value.find(boost::make_tuple(kvs.key, kvs.value));
    if (it == index_by_key_value.end())
      return bptime::neg_infin;
    return (*it).refresh_time;
  }

  uint16_t KDistanceTo(const NodeId &lhs, const NodeId &rhs) {
    uint16_t distance = 0;
    std::string this_id_binary = lhs.ToStringEncoded(NodeId::kBinary);
    std::string rhs_id_binary = rhs.ToStringEncoded(NodeId::kBinary);
    std::string::const_iterator this_it = this_id_binary.begin();
    std::string::const_iterator rhs_it = rhs_id_binary.begin();
    for (; ((this_it != this_id_binary.end()) && (*this_it == *rhs_it));
        ++this_it, ++rhs_it)
      ++distance;
    return distance;
  }

  int GetDistance(const std::vector<Contact> &list, int test) {
    int low(0), high(0);
    uint16_t distance = KDistanceTo(service_contact_.node_id(),
                                           list[0].node_id());
    low = distance;
    auto it = list.begin();
    while (it != list.end()) {
      distance = KDistanceTo(service_contact_.node_id(), (*it).node_id());
      if (distance > high)
        high = distance;
      else if (distance < low)
        low = distance;
      ++it;
    }
    if (test > 0)
      return high;
    else
      return low;
  }

  void StopAndReset() {
    asio_service_.Stop();
    local_asio_.Stop();
  }

  void SetContactValidation(bool validated) {
    if (validated)
      service_->set_contact_validator(std::bind(
          &RpcsTest::StubContactValidatorTrue, this, args::_1, args::_2,
          args::_3));
    else
      service_->set_contact_validator(std::bind(
          &RpcsTest::StubContactValidatorFalse, this, args::_1, args::_2,
          args::_3));
  }

  bool StubContactValidatorFalse(asymm::Identity /*identity*/,
                                 asymm::PublicKey /*public_key*/,
                                 asymm::ValidationToken /*validation_token*/) {
    return false;
  }

  bool StubContactValidatorTrue(asymm::Identity /*identity*/,
                                asymm::PublicKey /*public_key*/,
                                asymm::ValidationToken /*validation_token*/) {
    return true;
  }

 protected:
  typedef std::shared_ptr<boost::asio::io_service::work> WorkPtr;

  NodeId node_id_;
  std::shared_ptr<RoutingTable> routing_table_;
  std::shared_ptr<DataStore> data_store_;
  KeyPairPtr service_key_pair_;
  std::shared_ptr<Service> service_;
  KeyPairPtr rpcs_key_pair_;
  AsioService asio_service_, local_asio_;
  std::shared_ptr<Rpcs<T>> rpcs_;
  Contact rpcs_contact_;
  Contact service_contact_;
  static asymm::Keys sender_crypto_key_id_;
  static asymm::Keys receiver_crypto_key_id_;
  RankInfoPtr rank_info_;
  std::vector<Contact> contacts_;
  TransportPtr transport_;
  MessageHandlerPtr handler_;
};

template <typename T>
asymm::Keys RpcsTest<T>::sender_crypto_key_id_;
template <typename T>
asymm::Keys RpcsTest<T>::receiver_crypto_key_id_;

TYPED_TEST_CASE_P(RpcsTest);


TYPED_TEST_P(RpcsTest, FUNC_PingNoTarget) {
  bool done(false);
  int response_code(kGeneralError);

  this->rpcs_->Ping(GetPrivateKeyPtr(this->rpcs_key_pair_), this->rpcs_contact_,
      std::bind(&TestCallback, args::_1, args::_2, &done, &response_code));

  while (!done)
    Sleep(boost::posix_time::milliseconds(10));
  this->StopAndReset();

  EXPECT_GT(0, response_code);
}

TYPED_TEST_P(RpcsTest, FUNC_PingTarget) {
  bool done(false);
  int response_code(kPendingResult);
  this->rpcs_->Ping(GetPrivateKeyPtr(this->rpcs_key_pair_),
      this->service_contact_,
      std::bind(&TestCallback, args::_1, args::_2, &done, &response_code));

  while (!done)
    Sleep(boost::posix_time::milliseconds(10));
  this->StopAndReset();

  EXPECT_EQ(kSuccess, response_code);
}

TYPED_TEST_P(RpcsTest, FUNC_FindNodesEmptyRT) {
  // tests FindNodes using empty routing table
  bool done(false);
  int response_code(kGeneralError);
  std::vector<Contact> contact_list;
  Key key = this->service_contact_.node_id();

  this->rpcs_->FindNodes(key, g_kKademliaK,
                         GetPrivateKeyPtr(this->rpcs_key_pair_),
                         this->service_contact_,
                         std::bind(&TestFindNodesCallback, args::_1, args::_2,
                                   args::_3, &contact_list, &done,
                                   &response_code));
  while (!done)
    Sleep(boost::posix_time::milliseconds(10));
  this->StopAndReset();

  EXPECT_TRUE(contact_list.empty());
  EXPECT_EQ(kIterativeLookupFailed, response_code);
}

TYPED_TEST_P(RpcsTest, FUNC_FindNodesPopulatedRTnoNode) {
  // tests FindNodes with a populated routing table not containing the node
  // being sought
  bool done(false);
  int response_code(kGeneralError);
  std::vector<Contact> contact_list;
  this->PopulateRoutingTable(2*g_kKademliaK);
  Key key = this->service_contact_.node_id();

  this->rpcs_->FindNodes(key, g_kKademliaK,
                         GetPrivateKeyPtr(this->rpcs_key_pair_),
                         this->service_contact_,
                         std::bind(&TestFindNodesCallback, args::_1, args::_2,
                                   args::_3, &contact_list, &done,
                                   &response_code));
  while (!done)
    Sleep(boost::posix_time::milliseconds(10));
  this->StopAndReset();

  bool found(false);
  std::sort(contact_list.begin(), contact_list.end());
  auto it = contact_list.begin();
  while (it != contact_list.end()) {
    if ((*it).node_id() == this->service_contact_.node_id())
      found = true;
    for (size_t i = 0; i < this->contacts_.size(); i++) {
      if ((*it).node_id() == this->contacts_[i].node_id())
        this->contacts_.erase(this->contacts_.begin()+i);
      }
    ++it;
  }
  EXPECT_FALSE(found);
  EXPECT_GE(this->GetDistance(contact_list, 0),
            this->GetDistance(this->contacts_, 1));
  EXPECT_EQ(g_kKademliaK, contact_list.size());
  EXPECT_EQ(kSuccess, response_code);
}

TYPED_TEST_P(RpcsTest, FUNC_FindNodesPopulatedRTwithNode) {
  // tests FindNodes with a populated routing table which contains the node
  // being sought
  bool done(false);
  int response_code(kGeneralError);
  this->PopulateRoutingTable(2*g_kKademliaK-1);
  std::vector<Contact> contact_list;
  AddContact(this->routing_table_, this->service_contact_, this->rank_info_);
  Key key = this->service_contact_.node_id();

  this->rpcs_->FindNodes(key, g_kKademliaK,
                         GetPrivateKeyPtr(this->rpcs_key_pair_),
                         this->service_contact_,
                         std::bind(&TestFindNodesCallback, args::_1, args::_2,
                                   args::_3, &contact_list, &done,
                                   &response_code));
  while (!done)
    Sleep(boost::posix_time::milliseconds(10));
  this->StopAndReset();

  bool found(false);
  auto it = contact_list.begin();
  while (it != contact_list.end()) {
    if ((*it).node_id() == this->service_contact_.node_id())
      found = true;
    for (size_t i = 0; i < this->contacts_.size(); i++) {
      if ((*it).node_id() == this->contacts_[i].node_id())
        this->contacts_.erase(this->contacts_.begin()+i);
      }
    ++it;
  }
  EXPECT_TRUE(found);
  EXPECT_GE(this->GetDistance(contact_list, 0),
            this->GetDistance(this->contacts_, 1));
  EXPECT_EQ(g_kKademliaK, contact_list.size());
  EXPECT_EQ(kSuccess, response_code);
}

TYPED_TEST_P(RpcsTest, FUNC_FindNodesVariableNodesRequest) {
  // tests FindNodes with a populated routing table which contains the node
  // being sought, where num_nodes_requested < g_kKademliaK, it should return
  // g_kKademliaK contacts
  bool done(false);
  int response_code(kGeneralError);
  this->PopulateRoutingTable(2*g_kKademliaK-1);
  std::vector<Contact> contact_list;
  AddContact(this->routing_table_, this->service_contact_, this->rank_info_);
  Key key = this->service_contact_.node_id();

  this->rpcs_->FindNodes(key, g_kKademliaK/2,
                         GetPrivateKeyPtr(this->rpcs_key_pair_),
                         this->service_contact_,
                         std::bind(&TestFindNodesCallback, args::_1, args::_2,
                                   args::_3, &contact_list, &done,
                                   &response_code));
  while (!done)
    Sleep(boost::posix_time::milliseconds(10));
  EXPECT_EQ(g_kKademliaK, contact_list.size());
  EXPECT_EQ(kSuccess, response_code);

  // tests FindNodes with a populated routing table which contains the node
  // being sought, where num_nodes_requested > g_kKademliaK, it should return
  // num_nodes_requested
  done = false;
  response_code = kGeneralError;
  contact_list.clear();

  this->rpcs_->FindNodes(key, g_kKademliaK*3/2,
                         GetPrivateKeyPtr(this->rpcs_key_pair_),
                         this->service_contact_,
                         std::bind(&TestFindNodesCallback, args::_1, args::_2,
                                   args::_3, &contact_list, &done,
                                   &response_code));
  while (!done)
    Sleep(boost::posix_time::milliseconds(10));
  this->StopAndReset();
  EXPECT_EQ(g_kKademliaK*3/2, contact_list.size());
  EXPECT_EQ(kSuccess, response_code);
}

TYPED_TEST_P(RpcsTest, FUNC_FindValueVariableNodesRequest) {
  bool done(false);
  int response_code(kGeneralError);
  this->PopulateRoutingTable(2*g_kKademliaK);
  Key key = this->rpcs_contact_.node_id();
  KeyValueSignature kvs = MakeKVS(this->sender_crypto_key_id_, 1024,
                                  key.String(), "");
  boost::posix_time::seconds ttl(3600);

  std::vector<ValueAndSignature> return_values_and_signatures;
  std::vector<Contact> return_contacts;
  done = false;
  response_code = kGeneralError;

  // attempt to find a value when number_of_nodes_request < g_kKademliaK,
  // the response should contain g_kKademliaK nodes.
  this->rpcs_->FindValue(key, g_kKademliaK/2,
                         GetPrivateKeyPtr(this->rpcs_key_pair_),
                         this->service_contact_,
                         std::bind(&TestFindValueCallback, args::_1, args::_2,
                                   args::_3, args::_4, args::_5,
                                   &return_values_and_signatures,
                                   &return_contacts, &done, &response_code));

  while (!done)
    Sleep(boost::posix_time::milliseconds(10));
  EXPECT_EQ(kFailedToFindValue, response_code);
  EXPECT_EQ(g_kKademliaK, return_contacts.size());

  // attempt to find a value when number_of_nodes_request > g_kKademliaK,
  // the response should contain number_of_nodes_request nodes.
  return_values_and_signatures.clear();
  return_contacts.clear();
  done = false;
  response_code = kGeneralError;
  this->rpcs_->FindValue(key, g_kKademliaK*3/2,
                         GetPrivateKeyPtr(this->rpcs_key_pair_),
                         this->service_contact_,
                         std::bind(&TestFindValueCallback, args::_1, args::_2,
                                   args::_3, args::_4, args::_5,
                                   &return_values_and_signatures,
                                   &return_contacts, &done, &response_code));
  while (!done)
    Sleep(boost::posix_time::milliseconds(10));
  EXPECT_EQ(kFailedToFindValue, response_code);
  EXPECT_EQ(g_kKademliaK*3/2, return_contacts.size());
  this->StopAndReset();
}

TYPED_TEST_P(RpcsTest, FUNC_StoreAndFindValue) {
  bool done(false);
  int response_code(kGeneralError);
  this->PopulateRoutingTable(2*g_kKademliaK);
  Key key = this->rpcs_contact_.node_id();
  KeyValueSignature kvs = MakeKVS(this->sender_crypto_key_id_, 1024,
                                  key.String(), "");
  boost::posix_time::seconds ttl(3600);

  // attempt to find value before any stored
  std::vector<ValueAndSignature> return_values_and_signatures;
  std::vector<Contact> return_contacts;
  done = false;
  response_code = kGeneralError;
  this->rpcs_->FindValue(key, g_kKademliaK,
                         GetPrivateKeyPtr(this->rpcs_key_pair_),
                         this->service_contact_,
                         std::bind(&TestFindValueCallback, args::_1, args::_2,
                                   args::_3, args::_4, args::_5,
                                   &return_values_and_signatures,
                                   &return_contacts, &done, &response_code));

  while (!done)
    Sleep(boost::posix_time::milliseconds(10));
  EXPECT_EQ(kFailedToFindValue, response_code);
  EXPECT_TRUE(return_values_and_signatures.empty());
  EXPECT_EQ(g_kKademliaK, return_contacts.size());

  done = false;
  this->rpcs_->Store(key, kvs.value, kvs.signature, ttl,
                     GetPrivateKeyPtr(this->rpcs_key_pair_),
                     this->service_contact_,
                     std::bind(&TestCallback, args::_1, args::_2, &done,
                               &response_code));

  while (!done)
    Sleep(boost::posix_time::milliseconds(10));
  EXPECT_EQ(kSuccess, response_code);
  JoinNetworkLookup(this->service_key_pair_);

  // attempt to retrieve value stored
  return_values_and_signatures.clear();
  return_contacts.clear();
  done = false;
  response_code = kGeneralError;
  this->rpcs_->FindValue(key, g_kKademliaK,
                         GetPrivateKeyPtr(this->rpcs_key_pair_),
                         this->service_contact_,
                         std::bind(&TestFindValueCallback, args::_1, args::_2,
                                   args::_3, args::_4, args::_5,
                                   &return_values_and_signatures,
                                   &return_contacts, &done, &response_code));
  while (!done)
    Sleep(boost::posix_time::milliseconds(10));
  EXPECT_EQ(kSuccess, response_code);
  ASSERT_FALSE(return_values_and_signatures.empty());
  EXPECT_EQ(kvs.value, return_values_and_signatures[0].first);
  EXPECT_TRUE(return_contacts.empty());

  this->StopAndReset();
}

TYPED_TEST_P(RpcsTest, FUNC_StoreAndFindAndDeleteValueXXXToBeRemoved) {
  bool done(false);
  int response_code(kGeneralError);
  this->PopulateRoutingTable(2*g_kKademliaK);
  Key key = this->rpcs_contact_.node_id();
  KeyValueSignature kvs = MakeKVS(this->sender_crypto_key_id_, 1024,
                                  key.String(), "");
  boost::posix_time::seconds ttl(3600);

  // attempt to find value before any stored
  std::vector<ValueAndSignature> return_values_and_signatures;
  std::vector<Contact> return_contacts;
  done = false;
  response_code = kGeneralError;
  this->rpcs_->FindValue(key, g_kKademliaK,
                         GetPrivateKeyPtr(this->rpcs_key_pair_),
                         this->service_contact_,
                         std::bind(&TestFindValueCallback, args::_1, args::_2,
                                   args::_3, args::_4, args::_5,
                                   &return_values_and_signatures,
                                   &return_contacts, &done, &response_code));
  while (!done)
    Sleep(boost::posix_time::milliseconds(10));
  EXPECT_EQ(kFailedToFindValue, response_code);
  EXPECT_TRUE(return_values_and_signatures.empty());
  EXPECT_EQ(g_kKademliaK, return_contacts.size());

  done = false;
  response_code = kGeneralError;
  this->rpcs_->Store(key, kvs.value, kvs.signature, ttl,
                     GetPrivateKeyPtr(this->rpcs_key_pair_),
                     this->service_contact_,
                     std::bind(&TestCallback, args::_1, args::_2, &done,
                               &response_code));

  while (!done)
    Sleep(boost::posix_time::milliseconds(10));
  EXPECT_EQ(kSuccess, response_code);
  JoinNetworkLookup(this->service_key_pair_);

  // Allow for simulated delay in validation of request by service_.
  Sleep(kNetworkDelay);

  // attempt to retrieve value stored
  return_values_and_signatures.clear();
  return_contacts.clear();
  done = false;
  response_code = kGeneralError;
  this->rpcs_->FindValue(key, g_kKademliaK,
                         GetPrivateKeyPtr(this->rpcs_key_pair_),
                         this->service_contact_,
                         std::bind(&TestFindValueCallback, args::_1, args::_2,
                                   args::_3, args::_4, args::_5,
                                   &return_values_and_signatures,
                                   &return_contacts, &done, &response_code));
  while (!done)
    Sleep(boost::posix_time::milliseconds(10));
  EXPECT_EQ(kSuccess, response_code);
  EXPECT_EQ(kvs.value, return_values_and_signatures[0].first);
  EXPECT_TRUE(return_contacts.empty());

  this->rpcs_->Delete(key, kvs.value, kvs.signature,
      GetPrivateKeyPtr(this->rpcs_key_pair_),
      this->service_contact_, std::bind(&TestCallback, args::_1, args::_2,
                                        &done, &response_code));

  done = false;
  response_code = kGeneralError;
  while (!done)
    Sleep(boost::posix_time::milliseconds(10));
  EXPECT_EQ(kSuccess, response_code);
  JoinNetworkLookup(this->service_key_pair_);

  return_values_and_signatures.clear();
  return_contacts.clear();
  done = false;
  response_code = kGeneralError;
  this->rpcs_->FindValue(key, g_kKademliaK,
                         GetPrivateKeyPtr(this->rpcs_key_pair_),
                         this->service_contact_,
                         std::bind(&TestFindValueCallback, args::_1, args::_2,
                                   args::_3, args::_4, args::_5,
                                   &return_values_and_signatures,
                                   &return_contacts, &done, &response_code));
  while (!done)
    Sleep(boost::posix_time::milliseconds(10));
  this->StopAndReset();
  // Value deleted
  EXPECT_EQ(kFailedToFindValue, response_code);
  EXPECT_TRUE(return_values_and_signatures.empty());
  EXPECT_EQ(g_kKademliaK, return_contacts.size());
  EXPECT_FALSE(IsKeyValueInDataStore(kvs, this->data_store_));

  this->StopAndReset();
}

TYPED_TEST_P(RpcsTest, FUNC_StoreMalicious) {
  this->PopulateRoutingTable(2*g_kKademliaK);
  bool done(false);
  int response_code(kGeneralError);
  Key key = this->rpcs_contact_.node_id();
  boost::posix_time::seconds ttl(3600);
  KeyValueSignature kvs =
      MakeKVS(this->sender_crypto_key_id_, 1024, key.String(), "");
  asymm::PublicKey public_key;
  asymm::DecodePublicKey("Different Public Key found on Network Lookup!!",
                        &public_key);
  AddTestValidation(this->service_key_pair_,
                    this->rpcs_contact_.node_id().String(),
                    public_key);
  this->SetContactValidation(false);

  // Malicious sender sends fake public_key
  this->rpcs_->Store(key, kvs.value, kvs.signature, ttl,
                     GetPrivateKeyPtr(this->rpcs_key_pair_),
      this->service_contact_, std::bind(&TestCallback, args::_1, args::_2,
                                        &done, &response_code));

  while (!done)
    Sleep(boost::posix_time::milliseconds(10));
  // Sender receives kSuccess, but value not stored in receiver's datastore
  EXPECT_EQ(kSuccess, response_code);
  JoinNetworkLookup(this->service_key_pair_);

  std::vector<ValueAndSignature> return_values_and_signatures;
  std::vector<Contact> return_contacts;
  done = false;
  response_code = kGeneralError;
  this->rpcs_->FindValue(key, g_kKademliaK,
                         GetPrivateKeyPtr(this->rpcs_key_pair_),
                         this->service_contact_,
                         std::bind(&TestFindValueCallback, args::_1, args::_2,
                                   args::_3, args::_4, args::_5,
                                   &return_values_and_signatures,
                                   &return_contacts, &done, &response_code));
  while (!done)
    Sleep(boost::posix_time::milliseconds(10));
  // Value not stored in data store
  EXPECT_EQ(kFailedToFindValue, response_code);
  EXPECT_TRUE(return_values_and_signatures.empty());
  EXPECT_EQ(g_kKademliaK, return_contacts.size());
  EXPECT_FALSE(IsKeyValueInDataStore(kvs, this->data_store_));
  this->StopAndReset();
  this->SetContactValidation(true);
}

TYPED_TEST_P(RpcsTest, FUNC_StoreMultipleRequest) {
  bool done(false);
  Key key = this->rpcs_contact_.node_id();
  std::vector<KeyValueSignature> kvs_vector;
  std::vector<std::pair<bool, int>> status_response;
  boost::posix_time::seconds ttl(3600);

  for (size_t i = 0; i < 10; ++i) {
    kvs_vector.push_back(MakeKVS(this->sender_crypto_key_id_, 1024,
                                 key.String(), ""));
    status_response.push_back(std::make_pair(false, -1));
  }
  AddTestValidation(this->service_key_pair_,
                    this->rpcs_contact_.node_id().String(),
                    this->sender_crypto_key_id_.public_key);
  std::string signature("");

  for (size_t i = 0; i < 10; ++i) {
    if (i%2)
      signature = "invalid signature";
    else
      signature = kvs_vector[i].signature;
    this->rpcs_->Store(key, kvs_vector[i].value, signature, ttl,
        GetPrivateKeyPtr(this->rpcs_key_pair_), this->service_contact_,
        std::bind(&TestCallback, args::_1, args::_2, &status_response[i].first,
                  &status_response[i].second));
  }
  while (!done) {
    for (size_t i = 0; i < 10; ++i) {
      done = status_response[i].first;
      if (!done) {
        Sleep(boost::posix_time::milliseconds(10));
        --i;
      }
    }
  }
  JoinNetworkLookup(this->service_key_pair_);
  this->StopAndReset();

  // Checking results
  for (int i = 0; i < 10; ++i) {
    EXPECT_EQ(kSuccess, status_response[i].second);
    if (i%2)
      EXPECT_FALSE(IsKeyValueInDataStore(kvs_vector[i], this->data_store_));
    else
      EXPECT_TRUE(IsKeyValueInDataStore(kvs_vector[i], this->data_store_));
  }
}

TYPED_TEST_P(RpcsTest, FUNC_StoreRefresh) {
  this->PopulateRoutingTable(2*g_kKademliaK);
  bool done(false);
  int response_code(kGeneralError);
  std::vector<ValueAndSignature> return_values_and_signatures;
  std::vector<Contact> return_contacts;
  Key key = this->rpcs_contact_.node_id();
  boost::posix_time::seconds ttl(2);
  KeyValueSignature kvs = MakeKVS(this->sender_crypto_key_id_, 1024,
                                  key.String(), "");
  protobuf::StoreRequest store_request = MakeStoreRequest(this->rpcs_contact_,
                                                          kvs);
  std::string message = store_request.SerializeAsString();
  std::string store_message_sig;
  asymm::Sign(message, this->sender_crypto_key_id_.private_key,
             &store_message_sig);
  AddTestValidation(this->service_key_pair_,
                    this->rpcs_contact_.node_id().String(),
                    this->sender_crypto_key_id_.public_key);

  // send original store request
  this->rpcs_->Store(key, kvs.value, kvs.signature, ttl,
                     GetPrivateKeyPtr(this->rpcs_key_pair_),
      this->service_contact_, std::bind(&TestCallback, args::_1, args::_2,
                                        &done, &response_code));

  while (!done)
    Sleep(boost::posix_time::milliseconds(10));
  EXPECT_EQ(kSuccess, response_code);
  JoinNetworkLookup(this->service_key_pair_);
  bptime::ptime refresh_time_old = this->GetRefreshTime(kvs);
  Sleep(boost::posix_time::seconds(1));

  // send store refresh request
  done = false;
  response_code = kGeneralError;
  this->rpcs_->StoreRefresh(message, store_message_sig,
      GetPrivateKeyPtr(this->rpcs_key_pair_),
      this->service_contact_, std::bind(&TestCallback, args::_1, args::_2,
                                        &done, &response_code));

  while (!done)
    Sleep(boost::posix_time::milliseconds(10));
  JoinNetworkLookup(this->service_key_pair_);
  EXPECT_EQ(kSuccess, response_code);

  // attempt to find original value
  done = false;
  response_code = kGeneralError;
  return_values_and_signatures.clear();
  return_contacts.clear();
  this->rpcs_->FindValue(key, g_kKademliaK,
                         GetPrivateKeyPtr(this->rpcs_key_pair_),
                         this->service_contact_,
                         std::bind(&TestFindValueCallback, args::_1, args::_2,
                                   args::_3, args::_4, args::_5,
                                   &return_values_and_signatures,
                                   &return_contacts, &done, &response_code));

  while (!done)
    Sleep(boost::posix_time::milliseconds(10));
  EXPECT_EQ(kSuccess, response_code);
  EXPECT_EQ(kvs.value, return_values_and_signatures[0].first);
  EXPECT_TRUE(return_contacts.empty());
  EXPECT_GT(this->GetRefreshTime(kvs), refresh_time_old);

  // attempt store refresh then find - ttl has expired so refresh should be
  // unsuccessful and find should fail
  Sleep(boost::posix_time::seconds(1));
  done = false;
  response_code = kGeneralError;
  this->rpcs_->StoreRefresh(message, store_message_sig,
      GetPrivateKeyPtr(this->rpcs_key_pair_),
      this->service_contact_, std::bind(&TestCallback, args::_1, args::_2,
                                        &done, &response_code));

  while (!done)
    Sleep(boost::posix_time::milliseconds(10));
  JoinNetworkLookup(this->service_key_pair_);
  EXPECT_EQ(kSuccess, response_code);

  done = false;
  response_code = kGeneralError;
  return_values_and_signatures.clear();
  return_contacts.clear();
  this->rpcs_->FindValue(key, g_kKademliaK,
                         GetPrivateKeyPtr(this->rpcs_key_pair_),
                         this->service_contact_,
                         std::bind(&TestFindValueCallback, args::_1, args::_2,
                                   args::_3, args::_4, args::_5,
                                   &return_values_and_signatures,
                                   &return_contacts, &done, &response_code));

  while (!done)
    Sleep(boost::posix_time::milliseconds(10));
  EXPECT_EQ(kFailedToFindValue, response_code);
  EXPECT_TRUE(return_values_and_signatures.empty());
  EXPECT_EQ(g_kKademliaK, return_contacts.size());
  EXPECT_FALSE(IsKeyValueInDataStore(kvs, this->data_store_));

  this->StopAndReset();
}

// This test will fail (incorrectly allow values to be refreshed) until sender
// signature checking is in place for StoreRefresh
TYPED_TEST_P(RpcsTest, FUNC_StoreRefreshMultipleRequests) {
  std::vector<KeyValueSignature> kvs_vector;
  std::vector<std::pair<bool, int>> status_response;
  std::vector<bptime::ptime> refresh_time_old_vector;
  std::vector<RequestAndSignature> req_sig_vector;
  for (size_t i = 0; i < 10; ++i) {
    // Adding key value from different contact in the receiver's datastore
    NodeId sender_id = this->GenerateUniqueRandomId(this->node_id_, 502);
    kvs_vector.push_back(MakeKVS(this->sender_crypto_key_id_, 4096, "", ""));
    RequestAndSignature request_signature("", "");
    Contact sender = this->ComposeContactWithKey(sender_id, 5001,
                                           this->sender_crypto_key_id_);
    this->AddToReceiverDataStore(kvs_vector[i], this->sender_crypto_key_id_,
                                 sender, request_signature);
    req_sig_vector.push_back(request_signature);
    EXPECT_TRUE(IsKeyValueInDataStore(kvs_vector[i], this->data_store_));
    status_response.push_back(std::make_pair(false, -1));
    refresh_time_old_vector.push_back(this->GetRefreshTime(kvs_vector[i]));
    AddTestValidation(this->service_key_pair_, sender_id.String(),
                      this->sender_crypto_key_id_.public_key);
  }
  // Store Refresh rpc
  std::string req_signature;
  Sleep(boost::posix_time::seconds(2));
  for (size_t i = 0; i < 10; ++i) {
    if (i%2)
      req_signature = "Invalid Request Signature";
    else
      req_signature = req_sig_vector[i].second;
    this->rpcs_->StoreRefresh(req_sig_vector[i].first, req_signature,
        GetPrivateKeyPtr(this->rpcs_key_pair_), this->service_contact_,
        std::bind(&TestCallback, args::_1, args::_2, &status_response[i].first,
                  &status_response[i].second));
  }
  for (size_t i = 0; i < 10; ++i) {
    // Need to wait for invalid requests to timeout.
    while (!status_response[i].first)
      Sleep(boost::posix_time::milliseconds(1));
  }
  JoinNetworkLookup(this->service_key_pair_);
  this->StopAndReset();
  // Check results
  for (size_t i = 0; i < 10; ++i) {
    EXPECT_EQ(0, status_response[i].second);
    EXPECT_TRUE(IsKeyValueInDataStore(kvs_vector[i], this->data_store_));
    if (i%2) {
      EXPECT_EQ(this->GetRefreshTime(kvs_vector[i]),
                refresh_time_old_vector[i]);
    } else {
      EXPECT_GT(this->GetRefreshTime(kvs_vector[i]),
                refresh_time_old_vector[i]);
    }
  }
}

TYPED_TEST_P(RpcsTest, FUNC_StoreRefreshMalicious) {
  this->PopulateRoutingTable(2*g_kKademliaK);
  bool done(false);
  int response_code(kGeneralError);
  Key key = this->rpcs_contact_.node_id();
  boost::posix_time::seconds ttl(2);
  KeyValueSignature kvs =
      MakeKVS(this->sender_crypto_key_id_, 1024, key.String(), "");
  protobuf::StoreRequest store_request = MakeStoreRequest(this->rpcs_contact_,
                                                          kvs);
  std::string message = store_request.SerializeAsString();
  std::string store_message_sig;
  asymm::Sign(message, this->sender_crypto_key_id_.private_key,
             &store_message_sig);
  AddTestValidation(this->service_key_pair_,
                    this->rpcs_contact_.node_id().String(),
                    this->sender_crypto_key_id_.public_key);

  this->rpcs_->Store(key, kvs.value, kvs.signature, ttl,
      GetPrivateKeyPtr(this->rpcs_key_pair_),
      this->service_contact_, std::bind(&TestCallback, args::_1, args::_2,
                                        &done, &response_code));

  while (!done)
    Sleep(boost::posix_time::milliseconds(10));
  EXPECT_EQ(0, response_code);
  JoinNetworkLookup(this->service_key_pair_);

  // Attempt refresh with fake key
  Sleep(boost::posix_time::seconds(1));
  asymm::PublicKey public_key;
  asymm::DecodePublicKey("Different Public Key found on Network Lookup!!",
                        &public_key);
  AddTestValidation(this->service_key_pair_,
                    this->rpcs_contact_.node_id().String(),
                    public_key);
  Sleep(boost::posix_time::seconds(1));
  done = false;
  response_code = kGeneralError;
  this->rpcs_->StoreRefresh(message, store_message_sig,
      GetPrivateKeyPtr(this->rpcs_key_pair_),
      this->service_contact_, std::bind(&TestCallback, args::_1, args::_2,
                                        &done, &response_code));

  while (!done)
    Sleep(boost::posix_time::milliseconds(10));
  JoinNetworkLookup(this->service_key_pair_);
  EXPECT_EQ(kSuccess, response_code);

  // attempt to find value - refresh should have failed and ttl expired from
  // original store, so no value returned
  std::vector<ValueAndSignature> return_values_and_signatures;
  std::vector<Contact> return_contacts;
  done = false;
  response_code = kGeneralError;
  this->rpcs_->FindValue(key, g_kKademliaK,
                         GetPrivateKeyPtr(this->rpcs_key_pair_),
                         this->service_contact_,
                         std::bind(&TestFindValueCallback, args::_1, args::_2,
                                   args::_3, args::_4, args::_5,
                                   &return_values_and_signatures,
                                   &return_contacts, &done, &response_code));

  while (!done)
    Sleep(boost::posix_time::milliseconds(10));
  EXPECT_EQ(kFailedToFindValue, response_code);
  EXPECT_TRUE(return_values_and_signatures.empty());
  EXPECT_EQ(g_kKademliaK, return_contacts.size());
  EXPECT_FALSE(IsKeyValueInDataStore(kvs, this->data_store_));

  this->StopAndReset();
}

TYPED_TEST_P(RpcsTest, FUNC_Delete) {
  this->PopulateRoutingTable(2*g_kKademliaK);
  bool done(false);
  int response_code(-1);
  Key key = this->rpcs_contact_.node_id();
  KeyValueSignature kvs =
      MakeKVS(this->sender_crypto_key_id_, 1024, key.String(), "");
  // Adding key value in the receiver's datastore
  RequestAndSignature request_signature("", "");
  this->AddToReceiverDataStore(kvs, this->sender_crypto_key_id_,
                               this->rpcs_contact_, request_signature);
  EXPECT_TRUE(IsKeyValueInDataStore(kvs, this->data_store_));
  AddTestValidation(this->service_key_pair_,
                    this->rpcs_contact_.node_id().String(),
                    this->sender_crypto_key_id_.public_key);

  this->rpcs_->Delete(key, kvs.value, kvs.signature,
                      GetPrivateKeyPtr(this->rpcs_key_pair_),
                      this->service_contact_, std::bind(&TestCallback, args::_1,
                                                        args::_2, &done,
                                                        &response_code));

  while (!done)
    Sleep(boost::posix_time::milliseconds(10));
  EXPECT_EQ(kSuccess, response_code);
  JoinNetworkLookup(this->service_key_pair_);

  std::vector<ValueAndSignature> return_values_and_signatures;
  std::vector<Contact> return_contacts;
  done = false;
  response_code = kGeneralError;
  this->rpcs_->FindValue(key, g_kKademliaK,
                         GetPrivateKeyPtr(this->rpcs_key_pair_),
                         this->service_contact_,
                         std::bind(&TestFindValueCallback, args::_1, args::_2,
                                   args::_3, args::_4, args::_5,
                                   &return_values_and_signatures,
                                   &return_contacts, &done, &response_code));

  while (!done)
    Sleep(boost::posix_time::milliseconds(10));
  this->StopAndReset();
  // Value deleted
  EXPECT_EQ(kFailedToFindValue, response_code);
  EXPECT_TRUE(return_values_and_signatures.empty());
  EXPECT_EQ(g_kKademliaK, return_contacts.size());
  EXPECT_FALSE(IsKeyValueInDataStore(kvs, this->data_store_));
}

TYPED_TEST_P(RpcsTest, FUNC_DeleteMalicious) {
  bool done(false);
  int response_code(-1);
  Key key = this->rpcs_contact_.node_id();
  KeyValueSignature kvs =
      MakeKVS(this->sender_crypto_key_id_, 1024, key.String(), "");
  // Adding key value in the receiver's datastore
  RequestAndSignature request_signature("", "");
  this->AddToReceiverDataStore(kvs, this->sender_crypto_key_id_,
                               this->rpcs_contact_, request_signature);
  EXPECT_TRUE(IsKeyValueInDataStore(kvs, this->data_store_));
  asymm::PublicKey public_key;
  asymm::DecodePublicKey("Different Public Key found on Network Lookup!!",
                        &public_key);
  AddTestValidation(this->service_key_pair_,
                    this->rpcs_contact_.node_id().String(),
                    public_key);

  // Malicious sender sends fake public_key
  this->rpcs_->Delete(key, kvs.value, kvs.signature,
      GetPrivateKeyPtr(this->rpcs_key_pair_),
      this->service_contact_, std::bind(&TestCallback, args::_1, args::_2,
                                        &done, &response_code));

  while (!done)
    Sleep(boost::posix_time::milliseconds(10));
  // Sender receives kSuccess, but value not deleted from receiver's datastore
  EXPECT_EQ(kSuccess, response_code);
  JoinNetworkLookup(this->service_key_pair_);
  // attempt to retrieve value stored
  std::vector<ValueAndSignature> return_values_and_signatures;
  std::vector<Contact> return_contacts;
  return_values_and_signatures.clear();
  return_contacts.clear();
  done = false;
  response_code = -1;
  this->rpcs_->FindValue(key, g_kKademliaK,
                         GetPrivateKeyPtr(this->rpcs_key_pair_),
                         this->service_contact_,
                         std::bind(&TestFindValueCallback, args::_1, args::_2,
                                   args::_3, args::_4, args::_5,
                                   &return_values_and_signatures,
                                   &return_contacts, &done, &response_code));

  while (!done)
    Sleep(boost::posix_time::milliseconds(10));
  this->StopAndReset();
  // Value not deleted from data store
  EXPECT_EQ(kSuccess, response_code);
  EXPECT_EQ(kvs.value, return_values_and_signatures[0].first);
  EXPECT_TRUE(return_contacts.empty());
  EXPECT_TRUE(IsKeyValueInDataStore(kvs, this->data_store_));
}

TYPED_TEST_P(RpcsTest, FUNC_DeleteNonExistingKey) {
  bool done(false);
  int response_code(-1);
  Key key = this->rpcs_contact_.node_id();
  KeyValueSignature kvs =
      MakeKVS(this->sender_crypto_key_id_, 1024, key.String(), "");

  EXPECT_FALSE(IsKeyValueInDataStore(kvs, this->data_store_));
  AddTestValidation(this->service_key_pair_,
                    this->rpcs_contact_.node_id().String(),
                    this->sender_crypto_key_id_.public_key);

  this->rpcs_->Delete(key, kvs.value, kvs.signature,
      GetPrivateKeyPtr(this->rpcs_key_pair_),
      this->service_contact_, std::bind(&TestCallback, args::_1, args::_2,
                                        &done, &response_code));

  while (!done)
    Sleep(boost::posix_time::milliseconds(10));
  this->StopAndReset();
  EXPECT_EQ(kSuccess, response_code);

  JoinNetworkLookup(this->service_key_pair_);
  EXPECT_FALSE(IsKeyValueInDataStore(kvs, this->data_store_));
}

TYPED_TEST_P(RpcsTest, FUNC_DeleteMultipleRequest) {
  bool done(false);
  Key key = this->rpcs_contact_.node_id();
  std::vector<KeyValueSignature> kvs_vector;
  std::vector<std::pair<bool, int>> status_response;

  for (size_t i = 0; i < 10; ++i) {
    kvs_vector.push_back(MakeKVS(this->sender_crypto_key_id_, 1024,
                                 key.String(), ""));
    status_response.push_back(std::make_pair(false, -1));
    RequestAndSignature request_signature("", "");
    this->AddToReceiverDataStore(kvs_vector[i], this->sender_crypto_key_id_,
                                 this->rpcs_contact_, request_signature);
    EXPECT_TRUE(IsKeyValueInDataStore(kvs_vector[i], this->data_store_));
  }
  AddTestValidation(this->service_key_pair_,
                    this->rpcs_contact_.node_id().String(),
                    this->sender_crypto_key_id_.public_key);
  std::string signature;

  for (size_t i = 0; i < 10; ++i) {
    if (i % 2)
      signature = "invalid signature";
    else
      asymm::Sign(kvs_vector[i].value,
                 this->sender_crypto_key_id_.private_key,
                 &signature);
    this->rpcs_->Delete(key, kvs_vector[i].value, signature,
                        GetPrivateKeyPtr(
                            this->rpcs_key_pair_),
                            this->service_contact_,
                            std::bind(&TestCallback, args::_1, args::_2,
                                      &status_response[i].first,
                                      &status_response[i].second));
  }
  while (!done) {
    for (size_t i = 0; i < 10; ++i) {
      done = status_response[i].first;
      if (!done) {
        Sleep(boost::posix_time::milliseconds(10));
        --i;
      }
    }
  }
  this->StopAndReset();
  JoinNetworkLookup(this->service_key_pair_);

  // Checking results
  for (int i = 0; i < 10; ++i) {
    EXPECT_EQ(kSuccess, status_response[i].second) << "Failed index: " << i;
    if (i % 2)
      EXPECT_TRUE(IsKeyValueInDataStore(kvs_vector[i], this->data_store_));
    else
      EXPECT_FALSE(IsKeyValueInDataStore(kvs_vector[i], this->data_store_));
  }
}

TYPED_TEST_P(RpcsTest, FUNC_DeleteRefresh) {
  this->PopulateRoutingTable(2*g_kKademliaK);
  bool done(false);
  int response_code(-1);
  // Adding key value from different contact in the receiver's datastore
  NodeId sender_id = this->GenerateUniqueRandomId(this->node_id_, 502);
  asymm::Keys crypto_key_data;
  asymm::GenerateKeyPair(&crypto_key_data);
  Contact sender = this->ComposeContactWithKey(sender_id, 5001,
                                               crypto_key_data);
  Key key = sender.node_id();
  KeyValueSignature kvs = MakeKVS(crypto_key_data, 4096, key.String(), "");
  RequestAndSignature request_signature("", "");
  this->AddToReceiverDataStore(kvs, crypto_key_data, sender, request_signature);
  EXPECT_TRUE(IsKeyValueInDataStore(kvs, this->data_store_));

  AddTestValidation(this->service_key_pair_, sender_id.String(),
                    crypto_key_data.public_key);
  // Deleting
  this->DeleteFromReceiverDataStore(kvs, crypto_key_data, sender,
                                    request_signature);
  EXPECT_FALSE(IsKeyValueInDataStore(kvs, this->data_store_));
  bptime::ptime refresh_time_old = this->GetRefreshTime(kvs);

  this->rpcs_->DeleteRefresh(request_signature.first, request_signature.second,
                             GetPrivateKeyPtr(this->rpcs_key_pair_),
                             this->service_contact_,
                             std::bind(&TestCallback, args::_1, args::_2, &done,
                                       &response_code));

  while (!done)
    Sleep(boost::posix_time::milliseconds(10));
  EXPECT_EQ(kSuccess, response_code);
  JoinNetworkLookup(this->service_key_pair_);

  std::vector<ValueAndSignature> return_values_and_signatures;
  std::vector<Contact> return_contacts;
  done = false;
  response_code = -1;
  this->rpcs_->FindValue(key, g_kKademliaK,
                         GetPrivateKeyPtr(this->rpcs_key_pair_),
                         this->service_contact_,
                         std::bind(&TestFindValueCallback, args::_1, args::_2,
                                   args::_3, args::_4, args::_5,
                                   &return_values_and_signatures,
                                   &return_contacts, &done, &response_code));

  while (!done)
    Sleep(boost::posix_time::milliseconds(10));
  this->StopAndReset();

  EXPECT_EQ(kFailedToFindValue, response_code);
  EXPECT_TRUE(return_values_and_signatures.empty());
  EXPECT_EQ(g_kKademliaK, return_contacts.size());
  EXPECT_FALSE(IsKeyValueInDataStore(kvs, this->data_store_));
  // Refreshed
  EXPECT_GT(this->GetRefreshTime(kvs), refresh_time_old);
}

TYPED_TEST_P(RpcsTest, FUNC_DeleteRefreshStoredValue) {
  this->PopulateRoutingTable(2*g_kKademliaK);
  bool done(false);
  int response_code(-1);
  // Adding key value from different contact in the receiver's datastore
  NodeId sender_id = this->GenerateUniqueRandomId(this->node_id_, 502);
  asymm::Keys crypto_key_data;
  asymm::GenerateKeyPair(&crypto_key_data);
  Contact sender = this->ComposeContactWithKey(sender_id, 5001,
                                               crypto_key_data);
  Key key = sender.node_id();
  RequestAndSignature request_sig("", "");
  KeyValueSignature kvs = MakeKVS(crypto_key_data, 1024, key.String(), "");
  this->AddToReceiverDataStore(kvs, crypto_key_data, sender, request_sig);
  EXPECT_TRUE(IsKeyValueInDataStore(kvs, this->data_store_));

  AddTestValidation(this->service_key_pair_, sender_id.String(),
                    crypto_key_data.public_key);
  // Value not deleted
  RequestAndSignature request_signature("", "");
  EXPECT_TRUE(IsKeyValueInDataStore(kvs, this->data_store_));
  bptime::ptime refresh_time_old = this->GetRefreshTime(kvs);

  // Delete refresh without deleting
  this->rpcs_->DeleteRefresh(request_signature.first, request_signature.second,
      GetPrivateKeyPtr(this->rpcs_key_pair_), this->service_contact_,
      std::bind(&TestCallback, args::_1, args::_2, &done, &response_code));

  while (!done)
    Sleep(boost::posix_time::milliseconds(10));
  EXPECT_NE(kSuccess, response_code);
  JoinNetworkLookup(this->service_key_pair_);

  std::vector<ValueAndSignature> return_values_and_signatures;
  std::vector<Contact> return_contacts;
  done = false;
  response_code = -1;
  this->rpcs_->FindValue(key, g_kKademliaK,
                         GetPrivateKeyPtr(this->rpcs_key_pair_),
                         this->service_contact_,
                         std::bind(&TestFindValueCallback, args::_1, args::_2,
                                   args::_3, args::_4, args::_5,
                                   &return_values_and_signatures,
                                   &return_contacts, &done, &response_code));

  while (!done)
    Sleep(boost::posix_time::milliseconds(10));
  this->StopAndReset();
  // Value present in data store
  EXPECT_EQ(kSuccess, response_code);
  EXPECT_EQ(kvs.value, return_values_and_signatures[0].first);
  EXPECT_TRUE(return_contacts.empty());

  EXPECT_TRUE(IsKeyValueInDataStore(kvs, this->data_store_));
  // Not Refreshed
  EXPECT_EQ(this->GetRefreshTime(kvs), refresh_time_old);
}

TYPED_TEST_P(RpcsTest, FUNC_DeleteRefreshMalicious) {
  bool done(false);
  int response_code(-1);
  // Adding key value from different contact in the receiver's datastore
  NodeId sender_id = this->GenerateUniqueRandomId(this->node_id_, 502);
  asymm::Keys crypto_key_data;
  asymm::GenerateKeyPair(&crypto_key_data);
  KeyValueSignature kvs = MakeKVS(crypto_key_data, 4096, "", "");
  Contact sender = this->ComposeContactWithKey(sender_id, 5001,
                                               crypto_key_data);
  RequestAndSignature request_signature("", "");
  this->AddToReceiverDataStore(kvs, crypto_key_data, sender, request_signature);
  EXPECT_TRUE(IsKeyValueInDataStore(kvs, this->data_store_));

  // Deleting
  this->DeleteFromReceiverDataStore(kvs, crypto_key_data, sender,
                                    request_signature);
  EXPECT_FALSE(IsKeyValueInDataStore(kvs, this->data_store_));
  bptime::ptime refresh_time_old = this->GetRefreshTime(kvs);
  asymm::PublicKey public_key;
  asymm::DecodePublicKey("Different Public Key found on Network Lookup!!",
                        &public_key);
  AddTestValidation(this->service_key_pair_, sender_id.String(),
                    public_key);
  // Malicious sender sends fake public_key
  this->rpcs_->DeleteRefresh(request_signature.first, request_signature.second,
      GetPrivateKeyPtr(this->rpcs_key_pair_), this->service_contact_,
      std::bind(&TestCallback, args::_1, args::_2, &done, &response_code));

  while (!done)
    Sleep(boost::posix_time::milliseconds(10));
  EXPECT_EQ(kSuccess, response_code);

  this->StopAndReset();
  JoinNetworkLookup(this->service_key_pair_);
  EXPECT_FALSE(IsKeyValueInDataStore(kvs, this->data_store_));
  EXPECT_EQ(this->GetRefreshTime(kvs), refresh_time_old);
}

TYPED_TEST_P(RpcsTest, FUNC_DeleteRefreshNonExistingKey) {
  bool done(false);
  int response_code(-1);
  // Creating Delete request
  NodeId sender_id = this->GenerateUniqueRandomId(this->node_id_, 502);
  asymm::Keys crypto_key_data;
  asymm::GenerateKeyPair(&crypto_key_data);
  KeyValueSignature kvs = MakeKVS(crypto_key_data, 4096, "", "");
  Contact sender = this->ComposeContactWithKey(sender_id, 5001,
                                               crypto_key_data);
  protobuf::DeleteRequest delete_request = MakeDeleteRequest(sender, kvs);
  AddTestValidation(this->service_key_pair_, sender_id.String(),
                    crypto_key_data.public_key);
  std::string delete_message = delete_request.SerializeAsString();
  std::string delete_message_sig;
  asymm::Sign(delete_message, crypto_key_data.private_key, &delete_message_sig);
  RequestAndSignature request_signature(delete_message, delete_message_sig);
  // Sending delete refresh
  this->rpcs_->DeleteRefresh(request_signature.first, request_signature.second,
      GetPrivateKeyPtr(this->rpcs_key_pair_), this->service_contact_,
      std::bind(&TestCallback, args::_1, args::_2, &done, &response_code));

  while (!done)
    Sleep(boost::posix_time::milliseconds(10));
  EXPECT_EQ(kSuccess, response_code);

  this->StopAndReset();
  JoinNetworkLookup(this->service_key_pair_);
  EXPECT_FALSE(IsKeyValueInDataStore(kvs, this->data_store_));
}

// This test will fail (incorrectly allow values to be refreshed) until sender
// signature checking is in place for DeleteRefresh
TYPED_TEST_P(RpcsTest, FUNC_DeleteRefreshMultipleRequests) {
  bool done(false);
  std::vector<KeyValueSignature> kvs_vector;
  std::vector<std::pair<bool, int>> status_response;
  std::vector<bptime::ptime> refresh_time_old_vector;
  std::vector<RequestAndSignature> req_sig_vector;
  for (size_t i = 0; i < 10; ++i) {
    // Adding key value from different contact in the receiver's datastore
    NodeId sender_id = this->GenerateUniqueRandomId(this->node_id_, 502);
    asymm::Keys crypto_key_data;
    asymm::GenerateKeyPair(&crypto_key_data);
    kvs_vector.push_back(MakeKVS(crypto_key_data, 4096, "", ""));
    Contact sender = this->ComposeContactWithKey(sender_id, 5001,
                                                 crypto_key_data);
    RequestAndSignature request_signature("", "");
    this->AddToReceiverDataStore(kvs_vector[i], crypto_key_data, sender,
                           request_signature);
    EXPECT_TRUE(IsKeyValueInDataStore(kvs_vector[i], this->data_store_));
    status_response.push_back(std::make_pair(false, -1));

    // Deleting
    this->DeleteFromReceiverDataStore(kvs_vector[i], crypto_key_data, sender,
                                request_signature);
    req_sig_vector.push_back(request_signature);
    EXPECT_FALSE(IsKeyValueInDataStore(kvs_vector[i], this->data_store_));
    refresh_time_old_vector.push_back(this->GetRefreshTime(kvs_vector[i]));
    AddTestValidation(this->service_key_pair_, sender_id.String(),
                      crypto_key_data.public_key);
  }
  // Delete Refresh rpc
  std::string req_signature;
  for (size_t i = 0; i < 10; ++i) {
    if (i%2)
      req_signature = "Invalid Request Signature";
    else
      req_signature = req_sig_vector[i].second;
    this->rpcs_->DeleteRefresh(req_sig_vector[i].first, req_signature,
        GetPrivateKeyPtr(this->rpcs_key_pair_), this->service_contact_,
        std::bind(&TestCallback, args::_1, args::_2, &status_response[i].first,
                  &status_response[i].second));
  }
  while (!done) {
    for (size_t i = 0; i < 10; ++i) {
      done = status_response[i].first;
      if (!done) {
        Sleep(boost::posix_time::milliseconds(10));
        --i;
      }
    }
  }
  this->StopAndReset();
  JoinNetworkLookup(this->service_key_pair_);
  // Checking results
  for (size_t i = 0; i < 10; ++i) {
    EXPECT_EQ(kSuccess, status_response[i].second);
    EXPECT_FALSE(IsKeyValueInDataStore(kvs_vector[i], this->data_store_));
    if (i%2) {
      EXPECT_EQ(this->GetRefreshTime(kvs_vector[i]),
                refresh_time_old_vector[i]);
    } else {
      EXPECT_GT(this->GetRefreshTime(kvs_vector[i]),
                refresh_time_old_vector[i]);
    }
  }
}

TYPED_TEST_P(RpcsTest, FUNC_DifferentSecurifier) {
  // Another securifier
  asymm::Keys key_pair2;
  asymm::GenerateKeyPair(&key_pair2);
  NodeId node_id2(NodeId::kRandomId);
  key_pair2.identity = node_id2.String();
  KeyPairPtr other_securifier(new asymm::Keys(key_pair2));


  // Send Ping
  bool done(false);
  int response_code(kPendingResult), count(0);
  this->rpcs_->Ping(this->GetPrivateKeyPtr(other_securifier),
                    this->service_contact_,
                    std::bind(&TestCallback, args::_1, args::_2,
                              &done, &response_code));

  while (!done && count++ < 1000)
    Sleep(transport::kDefaultInitialTimeout / 1000);
  EXPECT_EQ(kSuccess, response_code);
  JoinNetworkLookup(this->service_key_pair_);

  // Send FindValue
  done = false;
  response_code = kPendingResult;
  count = 0;
  this->PopulateRoutingTable(2*g_kKademliaK);
  Key key = this->rpcs_contact_.node_id();
  KeyValueSignature kvs = MakeKVS(this->sender_crypto_key_id_, 1024,
                                  key.String(), "");
  boost::posix_time::seconds ttl(3600);

  std::vector<ValueAndSignature> return_values_and_signatures;
  std::vector<Contact> return_contacts;
  this->rpcs_->FindValue(key,
                         g_kKademliaK,
                         this->GetPrivateKeyPtr(other_securifier),
                         this->service_contact_,
                         std::bind(&TestFindValueCallback, args::_1, args::_2,
                                   args::_3, args::_4, args::_5,
                                   &return_values_and_signatures,
                                   &return_contacts, &done, &response_code));
  while (!done && count++ < 1000)
    Sleep(transport::kDefaultInitialTimeout / 1000);
  EXPECT_EQ(kFailedToFindValue, response_code);
  EXPECT_EQ(g_kKademliaK, return_contacts.size());
  JoinNetworkLookup(this->service_key_pair_);

  // FindNodes
  done = false;
  response_code = kPendingResult;
  count = 0;
  return_contacts.clear();
  this->rpcs_->FindNodes(key,
                         g_kKademliaK,
                         this->GetPrivateKeyPtr(other_securifier),
                         this->service_contact_,
                         std::bind(&TestFindNodesCallback, args::_1, args::_2,
                                   args::_3, &return_contacts, &done,
                                   &response_code));
  while (!done && count++ < 1000)
    Sleep(transport::kDefaultInitialTimeout / 1000);
  EXPECT_EQ(g_kKademliaK, return_contacts.size());
  EXPECT_EQ(kSuccess, response_code);
  JoinNetworkLookup(this->service_key_pair_);

  this->StopAndReset();
}

REGISTER_TYPED_TEST_CASE_P(RpcsTest,
                           FUNC_PingNoTarget,
                           FUNC_PingTarget,
                           FUNC_FindNodesEmptyRT,
                           FUNC_FindNodesPopulatedRTnoNode,
                           FUNC_FindNodesPopulatedRTwithNode,
                           FUNC_FindNodesVariableNodesRequest,
                           FUNC_FindValueVariableNodesRequest,
                           FUNC_StoreAndFindValue,
                           FUNC_StoreAndFindAndDeleteValueXXXToBeRemoved,
                           FUNC_StoreMalicious,
                           FUNC_StoreMultipleRequest,
                           FUNC_StoreRefresh,
                           FUNC_StoreRefreshMultipleRequests,
                           FUNC_StoreRefreshMalicious,
                           FUNC_Delete,
                           FUNC_DeleteMalicious,
                           FUNC_DeleteNonExistingKey,
                           FUNC_DeleteMultipleRequest,
                           FUNC_DeleteRefresh,
                           FUNC_DeleteRefreshStoredValue,
                           FUNC_DeleteRefreshMalicious,
                           FUNC_DeleteRefreshNonExistingKey,
                           FUNC_DeleteRefreshMultipleRequests,
                           FUNC_DifferentSecurifier);

typedef ::testing::Types<transport::RudpTransport,
                         transport::TcpTransport,
                         transport::UdpTransport> TransportTypes;
INSTANTIATE_TYPED_TEST_CASE_P(TheRpcTests, RpcsTest, TransportTypes);


template <typename T>
class RpcsMultiServerNodesTest : public CreateContactAndNodeId,
                                 public testing::Test {
 public:
  RpcsMultiServerNodesTest()
      : CreateContactAndNodeId(g_kKademliaK),
        node_id_(NodeId::kRandomId),
        routing_table_(),
        data_store_(),
        services_securifier_(),
        service_(),
        rpcs_key_pair_(),
        asio_services_(),
        local_asios_(),
        dispatcher_(),
        rpcs_(),
        rpcs_contact_(),
        service_contact_(),
        rank_info_(),
        contacts_(),
        transport_(),
        handler_() {
    for (int index = 0; index < g_kRpcClientNo; ++index) {
      asio_services_.push_back(std::shared_ptr<AsioService>(new AsioService));
      (*asio_services_.rbegin())->Start(1);
    }
    const int kMinServerPositionOffset(kKeySizeBits - g_kRpcServersNo);
    for (int index = 0; index != g_kRpcServersNo; ++index) {
      NodeId service_node_id =
          GenerateRandomId(node_id_, kMinServerPositionOffset + index);
      routing_table_.push_back(RoutingTablePtr(new RoutingTable(service_node_id,
                                                                g_kKademliaK)));
      data_store_.push_back(DataStorePtr(
          new DataStore(bptime::seconds(3600))));
      local_asios_.push_back(std::shared_ptr<AsioService>(new AsioService));
      (*local_asios_.rbegin())->Start(1);
    }
    dispatcher_.Start(1);
  }

  static void SetUpTestCase() {
    for (int index = 0; index < g_kRpcClientNo; ++index) {
      asymm::Keys temp_key_pair;
      asymm::GenerateKeyPair(&temp_key_pair);
      senders_crypto_key_id3_.push_back(temp_key_pair);
    }
    for (int index = 0; index < g_kRpcServersNo; ++index) {
      asymm::Keys temp_key_pair;
      asymm::GenerateKeyPair(&temp_key_pair);
      receivers_crypto_key_id3_.push_back(temp_key_pair);
    }
  }

  PrivateKeyPtr GetPrivateKeyPtr(KeyPairPtr key_pair) {
    return PrivateKeyPtr(new asymm::PrivateKey(key_pair->private_key));
  }

  virtual void SetUp() {
    // rpcs setup
    size_t port_start(RandomUint32() % 50000 + 1025);
    const int kMinClientPositionOffset(kKeySizeBits - g_kRpcClientNo);
    for (int index = 0; index != g_kRpcClientNo; ++index) {
      NodeId rpcs_node_id =
          GenerateRandomId(node_id_, kMinClientPositionOffset + index);
      asymm::Keys key_pair;
      key_pair.identity = rpcs_node_id.String();
      key_pair.private_key = senders_crypto_key_id3_[index].private_key;
      key_pair.public_key = senders_crypto_key_id3_[index].public_key;
      rpcs_key_pair_.push_back(KeyPairPtr(new asymm::Keys(key_pair)));
      rpcs_.push_back(std::shared_ptr<Rpcs<T>>(               // NOLINT (Fraser)
          new Rpcs<T>(asio_services_[index]->service(),
                      GetPrivateKeyPtr(rpcs_key_pair_[index]))));

      Contact rpcs_contact;
      rpcs_contact = ComposeContactWithKey(rpcs_node_id,
                         static_cast<Port>(port_start + index),
                         senders_crypto_key_id3_[index]);
      rpcs_contact_.push_back(rpcs_contact);
      rpcs_[index]->set_contact(rpcs_contact_[index]);
    }
    // service setup
    const int kMinServerPositionOffset(kKeySizeBits - g_kRpcServersNo);
    for (int index = 0; index != g_kRpcServersNo; ++index) {
      NodeId service_node_id =
          GenerateRandomId(node_id_, kMinServerPositionOffset + index);
      service_contact_.push_back(
          ComposeContactWithKey(service_node_id,
              static_cast<Port>(port_start + g_kRpcClientNo + index),
                                receivers_crypto_key_id3_[index]));
      asymm::Keys key_pair;
      key_pair.identity = service_node_id.String();
      key_pair.private_key = receivers_crypto_key_id3_[index].private_key;
      key_pair.public_key = receivers_crypto_key_id3_[index].public_key;
      services_securifier_.push_back(KeyPairPtr(new asymm::Keys(key_pair)));
      service_.push_back(
          ServicePtr(new Service(routing_table_[index], data_store_[index],
                                 GetPrivateKeyPtr(services_securifier_[index]),
                                 g_kKademliaK)));
      service_[index]->set_node_contact(service_contact_[index]);
      service_[index]->set_node_joined(true);
      transport_.push_back(TransportPtr(new T(local_asios_[index]->service())));
      handler_.push_back(
          MessageHandlerPtr(new MessageHandler(
              GetPrivateKeyPtr(services_securifier_[index]))));
      service_[index]->ConnectToSignals(handler_[index]);
      transport_[index]->on_message_received()->connect(
          transport::OnMessageReceived::element_type::slot_type(
              &MessageHandler::OnMessageReceived, handler_[index].get(),
              _1, _2, _3, _4).track_foreign(handler_[index]));
      EXPECT_EQ(kSuccess,
                transport_[index]->StartListening(
                                       service_contact_[index].endpoint()));
    }
  }

  ~RpcsMultiServerNodesTest() {
    std::for_each(asio_services_.begin(), asio_services_.end(),
                  [](std::shared_ptr<AsioService> asio_service) {
        asio_service->Stop();
    });
    std::for_each(local_asios_.begin(), local_asios_.end(),
                  [](std::shared_ptr<AsioService> asio_service) {
        asio_service->Stop();
    });
    dispatcher_.Stop();
  }

  void StopAndReset() {
    std::for_each(asio_services_.begin(), asio_services_.end(),
                  [](std::shared_ptr<AsioService> asio_service) {
        asio_service->Stop();
    });
    std::for_each(local_asios_.begin(), local_asios_.end(),
                  [](std::shared_ptr<AsioService> asio_service) {
        asio_service->Stop();
    });
  }

  void RpcOperations(const int index, const int server_index,
                     bool* done, int* response_code) {
    *done = false;
    *response_code = kGeneralError;
    bool ldone = false;
    Key key = rpcs_contact_[index].node_id();
    KeyValueSignature kvs = MakeKVS(senders_crypto_key_id3_[index], 1024,
                                    key.String(), "");
    boost::posix_time::seconds ttl(3600);
    // attempt to find value before any stored
    std::vector<ValueAndSignature> return_values_and_signatures;
    std::vector<Contact> return_contacts;
    *done = false;
    *response_code = kGeneralError;

    rpcs_[index]->FindValue(key, g_kKademliaK,
                            GetPrivateKeyPtr(rpcs_key_pair_[index]),
                            service_contact_[server_index],
                            std::bind(&TestFindValueCallback, args::_1,
                                      args::_2, args::_3, args::_4, args::_5,
                                      &return_values_and_signatures,
                                      &return_contacts, &ldone, response_code));
    while (!ldone)
      Sleep(boost::posix_time::milliseconds(10));

    // Returns kIterativeLookupFailed as the service has an empty routing table.
    EXPECT_EQ(kIterativeLookupFailed, *response_code);
    EXPECT_TRUE(return_values_and_signatures.empty());
    EXPECT_TRUE(return_contacts.empty());

    ldone = false;
    *response_code = kGeneralError;
    rpcs_[index]->Store(key, kvs.value, kvs.signature, ttl,
                        GetPrivateKeyPtr(rpcs_key_pair_[index]),
                        service_contact_[server_index],
                        std::bind(&TestCallback, args::_1, args::_2, &ldone,
                                  response_code));
    while (!ldone)
      Sleep(boost::posix_time::milliseconds(10));

    EXPECT_EQ(0, *response_code);
    JoinNetworkLookup(services_securifier_[server_index]);

    // attempt to retrieve value stored
    return_values_and_signatures.clear();
    return_contacts.clear();
    ldone = false;
    *response_code = kGeneralError;
    rpcs_[index]->FindValue(key, g_kKademliaK,
                            GetPrivateKeyPtr(rpcs_key_pair_[index]),
                            service_contact_[server_index],
                            std::bind(&TestFindValueCallback, args::_1,
                                      args::_2, args::_3, args::_4, args::_5,
                                      &return_values_and_signatures,
                                      &return_contacts, &ldone, response_code));

    while (!ldone)
      Sleep(boost::posix_time::milliseconds(10));

    EXPECT_EQ(0, *response_code);
    EXPECT_EQ(kvs.value, return_values_and_signatures[0].first);
    EXPECT_TRUE(return_contacts.empty());

    ldone = false;
    *response_code = kGeneralError;
    rpcs_[index]->Delete(key, kvs.value, kvs.signature,
                         GetPrivateKeyPtr(rpcs_key_pair_[index]),
                         service_contact_[server_index],
                         std::bind(&TestCallback, args::_1, args::_2,
                                   &ldone, response_code));
    while (!ldone)
      Sleep(boost::posix_time::milliseconds(10));

    EXPECT_EQ(kSuccess, *response_code);
    JoinNetworkLookup(services_securifier_[server_index]);

    return_values_and_signatures.clear();
    return_contacts.clear();
    *done = false;
    *response_code = kGeneralError;
    rpcs_[index]->FindValue(key, g_kKademliaK,
                            GetPrivateKeyPtr(rpcs_key_pair_[index]),
                            service_contact_[server_index],
                            std::bind(&TestFindValueCallback, args::_1,
                                      args::_2, args::_3, args::_4, args::_5,
                                      &return_values_and_signatures,
                                      &return_contacts, done, response_code));
    while (!*done)
      Sleep(boost::posix_time::milliseconds(10));

    // Value deleted.
    // Returns kIterativeLookupFailed as the service has an empty routing table.
    EXPECT_EQ(kIterativeLookupFailed, *response_code);
    EXPECT_TRUE(return_values_and_signatures.empty());
    EXPECT_TRUE(return_contacts.empty());
  }

 protected:
  typedef std::shared_ptr<boost::asio::io_service::work> WorkPtr;
  typedef std::shared_ptr<DataStore> DataStorePtr;
  typedef std::shared_ptr<RoutingTable> RoutingTablePtr;
  typedef std::shared_ptr<Service> ServicePtr;

  NodeId node_id_;
  std::vector<RoutingTablePtr> routing_table_;
  std::vector<DataStorePtr> data_store_;
  std::vector<KeyPairPtr> services_securifier_;
  std::vector<ServicePtr> service_;
  std::vector<KeyPairPtr> rpcs_key_pair_;
  std::vector<std::shared_ptr<AsioService>> asio_services_, local_asios_;
  AsioService dispatcher_;
  std::vector<std::shared_ptr<Rpcs<T>>> rpcs_;                // NOLINT (Fraser)
  std::vector<Contact> rpcs_contact_;
  std::vector<Contact> service_contact_;
  static std::vector<asymm::Keys> senders_crypto_key_id3_;
  static std::vector<asymm::Keys> receivers_crypto_key_id3_;
  RankInfoPtr rank_info_;
  std::vector<Contact> contacts_;
  std::vector<TransportPtr> transport_;
  std::vector<MessageHandlerPtr> handler_;
  std::vector<WorkPtr> work_;
  std::vector<WorkPtr> work1_;
};

template <typename T>
std::vector<asymm::Keys>
    RpcsMultiServerNodesTest<T>::senders_crypto_key_id3_;
template <typename T>
std::vector<asymm::Keys>
    RpcsMultiServerNodesTest<T>::receivers_crypto_key_id3_;


TYPED_TEST_CASE_P(RpcsMultiServerNodesTest);


TYPED_TEST_P(RpcsMultiServerNodesTest, FUNC_MultipleServerOperations) {
  bool done[g_kRpcClientNo][g_kRpcServersNo];
  bool localdone = false;
  int response_code[g_kRpcClientNo][g_kRpcServersNo];
  for (int client_index = 0; client_index < g_kRpcClientNo; ++client_index) {
    for (int index = 0; index < g_kRpcServersNo; ++index) {
      done[client_index][index] = false;
      response_code[client_index][index] = 0;
      // This is to enable having more than one operation
      this->dispatcher_.service().post(
          std::bind(&RpcsMultiServerNodesTest<TypeParam>::RpcOperations, this,
                    client_index, index, &done[client_index][index],
                    &response_code[client_index][index]));
    }
  }
  while (!localdone) {
    localdone = true;
    for (int client_index = 0; client_index < g_kRpcClientNo; ++client_index) {
      for (int index = 0; index < g_kRpcServersNo; ++index) {
        localdone = localdone && done[client_index][index];
      }
    }
    Sleep(boost::posix_time::milliseconds(10));
  }
  this->StopAndReset();
}

REGISTER_TYPED_TEST_CASE_P(RpcsMultiServerNodesTest,
                           FUNC_MultipleServerOperations);

INSTANTIATE_TYPED_TEST_CASE_P(TheMultiServerRpcTests, RpcsMultiServerNodesTest,
                              TransportTypes);

}  // namespace test

}  // namespace dht

}  // namespace maidsafe
