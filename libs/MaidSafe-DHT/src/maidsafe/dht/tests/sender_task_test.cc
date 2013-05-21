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


#include "boost/thread/thread.hpp"

#include "maidsafe/common/test.h"
#include "maidsafe/common/crypto.h"
#include "maidsafe/common/utils.h"
#include "maidsafe/dht/data_store.h"
#include "maidsafe/dht/sender_task.h"
#include "maidsafe/dht/tests/test_utils.h"

namespace args = std::placeholders;

namespace maidsafe {

namespace dht {

namespace test {

class SenderTaskTest: public testing::Test {
 public:
  SenderTaskTest()
      : info_(),
        sender_task_(new SenderTask),
        count_callback_1_(0),
        count_callback_2_(0),
        asio_thread_group_() {
  }

  virtual void SetUp() {}

  bool HasDataInIndex(const KeyValueSignature &key_value_signature,
                      const RequestAndSignature &request_signature,
                      const std::string &public_key_id) {
    if (key_value_signature.key.empty())
      return false;
    TaskIndex::index<TagTaskKey>::type& index_by_key =
        sender_task_->task_index_->get<TagTaskKey>();
    auto itr = index_by_key.equal_range(key_value_signature.key);
    for ( ; itr.first != itr.second; ++itr.first) {
      if ((*itr.first).key_value_signature.value == key_value_signature.value) {
        return (((*itr.first).key_value_signature.signature ==
                    key_value_signature.signature) &&
                ((*itr.first).request_signature == request_signature) &&
                ((*itr.first).public_key_id == public_key_id));
      }
    }
    return false;
  }

  void TestTaskCallBack1(KeyValueSignature,
                         std::string,
                         transport::Info,
                         RequestAndSignature,
                         std::string,
                         asymm::PublicKey,
                         asymm::ValidationToken) { ++count_callback_1_; }

  void TestTaskCallBack2(KeyValueSignature,
                         std::string,
                         transport::Info,
                         RequestAndSignature,
                         std::string,
                         asymm::PublicKey,
                         asymm::ValidationToken) { ++count_callback_2_; }

  size_t GetSenderTaskSize() {
    return sender_task_->task_index_->size();
  }

  void ResetCallbackCount() {
    count_callback_2_ = 0;
    count_callback_1_ = 0;
  }

 protected:
  // Dummy function to imitate Securifier::GetPublicKeyAndValidation
  void GetPublicKeyAndValidation(
      const std::string & public_key_id,
      asymm::GetPublicKeyAndValidationCallback callback) {
    asio_thread_group_.create_thread(std::bind(&SenderTaskTest::DummyFind,
                                               this, public_key_id, callback));
  }

  void DummyFind(const std::string&,
                 asymm::GetPublicKeyAndValidationCallback callback) {
    // Imitating delay in lookup for kNetworkDelay milliseconds
    Sleep(boost::posix_time::milliseconds(kNetworkDelay));
    callback(asymm::PublicKey(), "");
  }

  transport::Info info_;
  std::shared_ptr<SenderTask> sender_task_;
  volatile uint16_t count_callback_1_, count_callback_2_;
  boost::thread_group asio_thread_group_;
};

TEST_F(SenderTaskTest, BEH_AddTask) {
  asymm::Keys crypto_key_data;
  asymm::GenerateKeyPair(&  crypto_key_data);
  KeyValueSignature kvs = MakeKVS(crypto_key_data, 1024, "", "");
  RequestAndSignature request_signature("message", "message_signature");
  TaskCallback task_cb = std::bind(&SenderTaskTest::TestTaskCallBack1, this,
                                   args::_1, "request", args::_2, args::_3,
                                   "response", args::_4, args::_5);
  bool is_new_id(true);
  // Invalid tasks
  EXPECT_FALSE(sender_task_->AddTask(KeyValueSignature("", "", ""), info_,
                                     request_signature, "public_key_id_1",
                                     task_cb, &is_new_id));
  EXPECT_FALSE(sender_task_->AddTask(kvs, info_, RequestAndSignature("", ""),
                                     "public_key_id_1", task_cb, &is_new_id));
  EXPECT_FALSE(HasDataInIndex(kvs, RequestAndSignature("", ""),
                              "public_key_id_1"));
  EXPECT_FALSE(sender_task_->AddTask(kvs, info_, request_signature, "", task_cb,
                                     &is_new_id));
  EXPECT_FALSE(HasDataInIndex(kvs, request_signature, ""));
  EXPECT_FALSE(sender_task_->AddTask(kvs, info_, request_signature,
                                     "public_key_id_1", nullptr, &is_new_id));
  EXPECT_FALSE(HasDataInIndex(kvs, request_signature, "public_key_id_1"));
  // Valid task
  EXPECT_TRUE(sender_task_->AddTask(kvs, info_, request_signature,
                                    "public_key_id_1", task_cb, &is_new_id));
  EXPECT_TRUE(is_new_id);
  EXPECT_TRUE(HasDataInIndex(kvs, request_signature, "public_key_id_1"));
  EXPECT_EQ(size_t(1), GetSenderTaskSize());
  // Adding same task again
  EXPECT_TRUE(sender_task_->AddTask(kvs, info_, request_signature,
                                    "public_key_id_1", task_cb, &is_new_id));
  EXPECT_FALSE(is_new_id);
  EXPECT_EQ(size_t(2), GetSenderTaskSize());

  // Adding new task with same key-value different public_key_id
  EXPECT_FALSE(sender_task_->AddTask(kvs, info_, request_signature,
                                     "public_key_id_2", task_cb, &is_new_id));
  EXPECT_TRUE(is_new_id);
  EXPECT_FALSE(HasDataInIndex(kvs, request_signature, "public_key_id_2"));
  EXPECT_EQ(size_t(2), GetSenderTaskSize());

  { // Adding new task with same public key id
    asymm::GenerateKeyPair(&  crypto_key_data);
    KeyValueSignature kvs = MakeKVS(crypto_key_data, 1024, "", "");
    EXPECT_TRUE(sender_task_->AddTask(kvs, info_, request_signature,
                                      "public_key_id_1", task_cb, &is_new_id));
    EXPECT_FALSE(is_new_id);
    EXPECT_TRUE(HasDataInIndex(kvs, request_signature, "public_key_id_1"));
    EXPECT_EQ(size_t(3), GetSenderTaskSize());
  }
  // Adding new task with new public key id
  {
    asymm::GenerateKeyPair(&  crypto_key_data);
    KeyValueSignature kvs = MakeKVS(crypto_key_data, 1024, "", "");
    EXPECT_TRUE(sender_task_->AddTask(kvs, info_, request_signature,
                                      "public_key_id_2", task_cb, &is_new_id));
    EXPECT_TRUE(is_new_id);
    EXPECT_TRUE(HasDataInIndex(kvs, request_signature, "public_key_id_2"));
    EXPECT_EQ(size_t(4), GetSenderTaskSize());
  }
  // Adding new task with different callback
  {
    TaskCallback task_cb = std::bind(&SenderTaskTest::TestTaskCallBack2,
                                     this, args::_1, "request", args::_2,
                                     args::_3, "response", args::_4, args::_5);
    asymm::GenerateKeyPair(&  crypto_key_data);
    KeyValueSignature kvs = MakeKVS(crypto_key_data, 1024, "", "");
    EXPECT_TRUE(sender_task_->AddTask(kvs, info_, request_signature,
                                      "public_key_id_1", task_cb, &is_new_id));
    EXPECT_FALSE(is_new_id);
    EXPECT_TRUE(HasDataInIndex(kvs, request_signature, "public_key_id_1"));
    EXPECT_EQ(size_t(5), GetSenderTaskSize());
  }
}

TEST_F(SenderTaskTest, FUNC_SenderTaskCallback) {
  asymm::Keys crypto_key_data;
  RequestAndSignature request_signature("message", "message_signature");
  TaskCallback task_cb_1 = std::bind(&SenderTaskTest::TestTaskCallBack1,
                                     this, args::_1, "request", args::_2,
                                     args::_3, "response", args::_4, args::_5);
  bool is_new_id(true);
  asymm::GetPublicKeyAndValidationCallback sender_task_cb_1 =
      std::bind(&SenderTask::SenderTaskCallback, sender_task_,
                "public_key_id_1", args::_1, args::_2);
  // Invalid data
  asymm::GenerateKeyPair(&  crypto_key_data);
  KeyValueSignature kvs = MakeKVS(crypto_key_data, 1024, "", "");
  ASSERT_TRUE(sender_task_->AddTask(kvs, info_, request_signature,
                                    "public_key_id_1", task_cb_1, &is_new_id));
  sender_task_->SenderTaskCallback("", asymm::PublicKey(), "");
  EXPECT_EQ(size_t(1), GetSenderTaskSize());
  EXPECT_EQ(0u , count_callback_1_);
  // Valid data (public_key_id)
  sender_task_->SenderTaskCallback("public_key_id_1", asymm::PublicKey(),
                                   "public_key_validation");
  EXPECT_EQ(size_t(0), GetSenderTaskSize());
  EXPECT_EQ(1u , count_callback_1_);
  ResetCallbackCount();
  // Adding multiple task
  for (int i = 1; i < 11; ++i) {
    asymm::GenerateKeyPair(&  crypto_key_data);
    KeyValueSignature kvs = MakeKVS(crypto_key_data, 1024, "", "");
    EXPECT_TRUE(sender_task_->AddTask(kvs, info_, request_signature,
                "public_key_id_1", task_cb_1, &is_new_id));
    EXPECT_TRUE(HasDataInIndex(kvs, request_signature, "public_key_id_1"));
    EXPECT_EQ(size_t(i), GetSenderTaskSize());
  }
  // Calling Securifier
  GetPublicKeyAndValidation("public_key_id_1", sender_task_cb_1);

  asio_thread_group_.join_all();
  EXPECT_EQ(10u, count_callback_1_);
  EXPECT_EQ(size_t(0), GetSenderTaskSize());
}

TEST_F(SenderTaskTest, FUNC_SenderTaskCallbackMultiThreaded) {
  asymm::Keys crypto_key_data;
  RequestAndSignature request_signature("message", "message_signature");
  TaskCallback task_cb_1 = std::bind(&SenderTaskTest::TestTaskCallBack1,
                                     this, args::_1, "request", args::_2,
                                     args::_3, "response", args::_4, args::_5);
  TaskCallback task_cb_2 = std::bind(&SenderTaskTest::TestTaskCallBack2,
                                     this, args::_1, "request", args::_2,
                                     args::_3, "response", args::_4, args::_5);
  bool is_new_id(true);
  uint16_t i(0);
  // Tasks to be executed and removed
  for (i = 0; i < 10; ++i) {
    asymm::GenerateKeyPair(&  crypto_key_data);
    KeyValueSignature kvs = MakeKVS(crypto_key_data, 1024, "", "");
    EXPECT_TRUE(sender_task_->AddTask(kvs, info_, request_signature,
                "public_key_id_1", task_cb_1, &is_new_id));
    EXPECT_TRUE(HasDataInIndex(kvs, request_signature, "public_key_id_1"));
    asymm::GenerateKeyPair(&  crypto_key_data);
    kvs = MakeKVS(crypto_key_data, 1024, "", "");
    EXPECT_TRUE(sender_task_->AddTask(kvs, info_, request_signature,
                "public_key_id_1", task_cb_2, &is_new_id));
    EXPECT_TRUE(HasDataInIndex(kvs, request_signature, "public_key_id_1"));
    asymm::GenerateKeyPair(&  crypto_key_data);
    kvs = MakeKVS(crypto_key_data, 1024, "", "");
    EXPECT_TRUE(sender_task_->AddTask(kvs, info_, request_signature,
                "public_key_id_2", task_cb_1, &is_new_id));
    EXPECT_TRUE(HasDataInIndex(kvs, request_signature, "public_key_id_2"));
    asymm::GenerateKeyPair(&  crypto_key_data);
    kvs = MakeKVS(crypto_key_data, 1024, "", "");
    EXPECT_TRUE(sender_task_->AddTask(kvs, info_, request_signature,
                "public_key_id_2", task_cb_2, &is_new_id));
    EXPECT_TRUE(HasDataInIndex(kvs, request_signature, "public_key_id_2"));
  }
  EXPECT_EQ(size_t(i * 4), GetSenderTaskSize());
  std::vector<KeyValueSignature> kvs_vector;
  // Tasks added and not executed and removed
  for (i = 0; i < 3; ++i) {
    asymm::GenerateKeyPair(&  crypto_key_data);
    KeyValueSignature kvs = MakeKVS(crypto_key_data, 1024, "", "");
    kvs_vector.push_back(kvs);
    asio_thread_group_.create_thread(std::bind(&SenderTask::AddTask,
                                               sender_task_, kvs,
                                               info_, request_signature,
                                               "public_key_id_3", task_cb_1,
                                               &is_new_id));
    asymm::GenerateKeyPair(&  crypto_key_data);
    kvs = MakeKVS(crypto_key_data, 1024, "", "");
    kvs_vector.push_back(kvs);
    asio_thread_group_.create_thread(std::bind(&SenderTask::AddTask,
                                               sender_task_, kvs,
                                               info_, request_signature,
                                               "public_key_id_4", task_cb_2,
                                               &is_new_id));
  }
  asio_thread_group_.join_all();

  // Calling SenderTaskCallback
  asio_thread_group_.create_thread(std::bind(&SenderTask::SenderTaskCallback,
                                             sender_task_,
                                             "public_key_id_1",
                                             asymm::PublicKey(),
                                             "public_key_validation"));
  asio_thread_group_.create_thread(std::bind(&SenderTask::SenderTaskCallback,
                                             sender_task_,
                                             "public_key_id_2",
                                             asymm::PublicKey(),
                                             "public_key_validation"));
  asio_thread_group_.join_all();

  EXPECT_EQ(20u , count_callback_1_);
  EXPECT_EQ(20u , count_callback_2_);
  ASSERT_EQ(size_t(i * 2), kvs_vector.size());
  for (size_t k = 0; k < kvs_vector.size(); ++k) {
    EXPECT_TRUE(HasDataInIndex(kvs_vector[k], request_signature,
                               "public_key_id_3") ||
                HasDataInIndex(kvs_vector[k], request_signature,
                               "public_key_id_4"));
  }
  EXPECT_EQ(size_t(i * 2), GetSenderTaskSize());
}

}  // namespace test_sender_task

}  // namespace dht

}  // namespace maidsafe
