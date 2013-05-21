/* Copyright (c) 2009 maidsafe.net limited
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
#include "boost/thread/thread.hpp"
#include "boost/thread/barrier.hpp"
#include "boost/asio/io_service.hpp"

#include "maidsafe/common/asio_service.h"
#include "maidsafe/common/test.h"
#include "maidsafe/common/crypto.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/transport/utils.h"

#include "maidsafe/dht/log.h"
#include "maidsafe/dht/contact.h"
#include "maidsafe/dht/routing_table.h"
#include "maidsafe/dht/return_codes.h"
#include "maidsafe/dht/node_id.h"
#include "maidsafe/dht/tests/test_utils.h"

namespace maidsafe {

namespace dht {

namespace test {

static const uint16_t kThreadBarrierSize = 2;

class RoutingTableTest : public CreateContactAndNodeId,
                         public testing::TestWithParam<int> {
 public:
  RoutingTableTest()
      : CreateContactAndNodeId(static_cast<uint16_t>(GetParam())),
        rank_info_(),
        holder_id_(NodeId::kRandomId),
        k_(static_cast<uint16_t>(GetParam())),
        routing_table_(holder_id_, k_),
        contact_(ComposeContact(NodeId(NodeId::kRandomId), 6101)),
        thread_barrier_(new boost::barrier(kThreadBarrierSize)) {}

  // Methods for multithreaded test
  void DoAddContact(Contact contact) {
    thread_barrier_->wait();
    routing_table_.AddContact(contact, rank_info_);
    routing_table_.SetValidated(contact.node_id(), true);
  }

  void DoGetContact(NodeId node_id) {
    Contact contact;
    thread_barrier_->wait();
    routing_table_.GetContact(node_id, &contact);
    EXPECT_EQ(node_id, contact.node_id());
  }

  void DoGetCloseContacts(const size_t &count) {
    NodeId target_id(GenerateUniqueRandomId(holder_id_, 500));
    std::vector<Contact> close_contacts;
    std::vector<Contact> exclude_contacts;
    thread_barrier_->wait();
    routing_table_.GetCloseContacts(target_id, count, exclude_contacts,
                                    &close_contacts);
    EXPECT_EQ(size_t(count), close_contacts.size());
  }

  void DoSetPublicKey(NodeId node_id, std::string key) {
    thread_barrier_->wait();
    EXPECT_EQ(0, routing_table_.SetPublicKey(node_id, key));
  }

  void DoUpdateRankInfo(NodeId node_id, RankInfoPtr rank_info) {
    thread_barrier_->wait();
    EXPECT_EQ(0, routing_table_.UpdateRankInfo(node_id, rank_info));
  }

  void DoSetPreferredEndpoint(const NodeId node_id, IP ip) {
    thread_barrier_->wait();
    EXPECT_EQ(0, routing_table_.SetPreferredEndpoint(node_id, ip));
  }

  void DoAddRemoveContact(Contact contact) {
    routing_table_.AddContact(contact, rank_info_);
    thread_barrier_->wait();
    for (int i = 0; i <= kFailedRpcTolerance ; ++i)
      routing_table_.IncrementFailedRpcCount(contact.node_id());
  }

 protected:
  void SetUp() {}

  uint16_t GetKBucketCount() const {
    return routing_table_.KBucketCount();
  }

  uint16_t GetKBucketSizeForKey(const uint16_t &key) {
    return routing_table_.KBucketSizeForKey(key);
  }

  RoutingTableContactsContainer GetContainer() {
    return routing_table_.contacts_;
  }

  UnValidatedContactsContainer GetUnValidatedContactsContainer() {
    return routing_table_.unvalidated_contacts_;
  }

  size_t GetSize() {
    return routing_table_.Size();
  }

  void Clear() {
    routing_table_.Clear();
  }

  void CallToPrivateFunctions() {
    for (int i = 0; i < k_; ++i) {
      NodeId node_id = GenerateUniqueRandomId(holder_id_, kKeySizeBits - 2);
      Contact contact = ComposeContact(node_id, 5431);
      AddContact(contact);
      EXPECT_EQ(0U, routing_table_.KBucketIndex(contact.node_id()));
    }
    {
      NodeId node_id = GenerateUniqueRandomId(holder_id_, kKeySizeBits - 1);
      Contact contact = ComposeContact(node_id, 4321);
      AddContact(contact);
      Contact contact1 = routing_table_.GetLastSeenContact(0);
      EXPECT_EQ(contact1.node_id(), contact.node_id());
      EXPECT_EQ(2U, routing_table_.KBucketCount());
      EXPECT_EQ(1U, routing_table_.KBucketSizeForKey(0));
    }
    NodeId node_id = GenerateUniqueRandomId(holder_id_, 1);
    Contact contact = ComposeContact(node_id, 4323);
    AddContact(contact);
    uint16_t distance = routing_table_.KDistanceTo(node_id);
    EXPECT_EQ(kKeySizeBits - 2, distance);
  }

  void FillContactToRoutingTable() {
    for (uint16_t i = 0; i < k_; ++i) {
      Contact contact = ComposeContact(NodeId(NodeId::kRandomId), i + 6111);
      (i == (k_ -1) ) ? AddContact(contact_) :
          AddContact(contact);
    }
    EXPECT_EQ(k_, GetSize());
  }

  void AddContact(const Contact& contact) {
    routing_table_.AddContact(contact, rank_info_);
    routing_table_.SetValidated(contact.node_id(), true);
  }

  RankInfoPtr rank_info_;
  NodeId holder_id_;
  uint16_t k_;
  RoutingTable routing_table_;
  Contact contact_;
  std::shared_ptr<boost::barrier> thread_barrier_;
};

class RoutingTableSingleKTest : public RoutingTableTest {
 public:
  RoutingTableSingleKTest() : RoutingTableTest() {}
};

INSTANTIATE_TEST_CASE_P(VariantKValues, RoutingTableTest,
                        testing::Range(2, 21));

INSTANTIATE_TEST_CASE_P(SingleKValue, RoutingTableSingleKTest,
                        testing::Values(2, 16));

TEST_P(RoutingTableTest, BEH_CallToPrivateFunctions) {
  // Test Private member functions (GetLastSeenContact)
  // (kBucketIndex) (KBucketCount) (KbucketSizeForKey) (KDistanceTo)
  this->CallToPrivateFunctions();
}

TEST_P(RoutingTableTest, BEH_Constructor) {
  ASSERT_EQ(0U, GetSize());
  ASSERT_EQ(1U, GetKBucketCount());
}

TEST_P(RoutingTableTest, BEH_Clear) {
  // create a contact and add it into the routing table
  NodeId contact_id(NodeId::kRandomId);
  Contact contact = ComposeContact(contact_id, 5001);
  AddContact(contact);
  ASSERT_EQ(1U, GetSize());

  // Try to clear the routing table
  Clear();
  ASSERT_EQ(0U, GetSize());
  ASSERT_EQ(1U, GetKBucketCount());

  // Try to add the contact (default unvalidated)
  routing_table_.AddContact(contact, rank_info_);
  ASSERT_EQ(1U, GetUnValidatedContactsContainer().size());
  ASSERT_EQ(0U, GetSize());
  ASSERT_EQ(1U, GetKBucketCount());
}

TEST_P(RoutingTableTest, BEH_GetContact) {
  // create a contact and add it into the routing table
  NodeId contact_id(NodeId::kRandomId);
  Contact contact = ComposeContact(contact_id, 5001);
  AddContact(contact);

  // Try to get an exist contact
  Contact result;
  routing_table_.GetContact(contact_id, &result);
  ASSERT_EQ(contact_id, result.node_id());

  // Try to get a non-exist contact
  Contact non_exist_result;
  NodeId non_exist_contact_id(NodeId::kRandomId);
  routing_table_.GetContact(non_exist_contact_id, &non_exist_result);
  ASSERT_EQ(non_exist_result, Contact());

  // Try to overload with an exist contact
  routing_table_.GetContact(contact_id, &non_exist_result);
  ASSERT_NE(non_exist_result, Contact());

  // Try to get a un-validated contact
  Clear();
  Contact unvalidated_result;
  routing_table_.AddContact(contact, rank_info_);
  routing_table_.GetContact(contact_id, &unvalidated_result);
  ASSERT_EQ(unvalidated_result, Contact());
}

TEST_P(RoutingTableTest, BEH_SetValidated) {
  // Note: this test case might need to be modified once the signal slot
  // is connected (i.e. there is handler to set the Validated tag automaticaly)

  // Set one entry to Validated
  NodeId contact_id(NodeId::kRandomId);
  Contact contact = ComposeContact(contact_id, 5001);
  routing_table_.AddContact(contact, rank_info_);
  ASSERT_EQ(1U, GetUnValidatedContactsContainer().size());
  ASSERT_EQ(0U, GetContainer().size());
  routing_table_.SetValidated(contact_id, true);
  ASSERT_EQ(0U, GetUnValidatedContactsContainer().size());
  ASSERT_EQ(1U, GetContainer().size());

  // Set the entry to in-valid
  routing_table_.SetValidated(contact_id, false);
  ASSERT_EQ(0U, GetUnValidatedContactsContainer().size());
  ASSERT_EQ(0U, GetContainer().size());

  // Add the entry again
  routing_table_.AddContact(contact, rank_info_);
  ASSERT_EQ(1U, GetUnValidatedContactsContainer().size());
  ASSERT_EQ(0U, GetContainer().size());

  // Set the entry to in-valid, this shall remove the entry
  routing_table_.SetValidated(contact_id, false);
  ASSERT_EQ(0U, GetUnValidatedContactsContainer().size());
  ASSERT_EQ(0U, GetContainer().size());
}

TEST_P(RoutingTableTest, BEH_AddContactForRandomCommonLeadingBits) {
  // Compose contact with random common_leading_bits
  for (uint16_t i = 0; i < k_; ++i) {
    NodeId node_id = GenerateUniqueRandomId(holder_id_,
                                            511 - (RandomUint32() % 511));
    Contact contact = ComposeContact(node_id, 5111 + i);
    AddContact(contact);
  }

  NodeId node_id = GenerateUniqueRandomId(holder_id_, 511 - 9);
  Contact contact = ComposeContact(node_id, 5113);
  AddContact(contact);
  uint16_t num_of_contacts(0);
  for (uint16_t i = 0; i < GetKBucketCount(); ++i) {
    uint16_t contacts_in_bucket = GetKBucketSizeForKey(i);
    EXPECT_GE(k_, contacts_in_bucket);
    num_of_contacts += contacts_in_bucket;
  }
  EXPECT_EQ(num_of_contacts, GetSize());
  EXPECT_LT(1U, GetKBucketCount());
}

TEST_P(RoutingTableTest, BEH_AddContactForHigherCommonLeadingBits) {
  // GenerateUniqueRandomId will flip the bit specified by the position
  // so the i=0 one will be the different to the holderId
  for (uint16_t i = 0; i < k_; ++i) {
    NodeId node_id = GenerateUniqueRandomId(holder_id_, i);
    Contact contact = ComposeContact(node_id, 5111 + i);
    AddContact(contact);
  }

  NodeId node_id = GenerateUniqueRandomId(holder_id_, 9);
  Contact contact = ComposeContact(node_id, 5113);
  AddContact(contact);
  EXPECT_EQ(k_ + 1, GetSize());
  uint16_t expected_kbucket_count = kKeySizeBits - (k_ - 2);
  if (k_ <= 9 )
    expected_kbucket_count = kKeySizeBits - 9 + 1;
  EXPECT_EQ(expected_kbucket_count, GetKBucketCount());
}

TEST_P(RoutingTableSingleKTest, FUNC_ForceKAcceptNewPeer) {
  // As this test is not multi-threaded, for convenience we can safely use an
  // upgrade lock on a shared mutex which isn't the routing table's member mutex
  boost::shared_mutex shared_mutex;
  std::shared_ptr<boost::upgrade_lock<boost::shared_mutex>> upgrade_lock(
      new boost::upgrade_lock<boost::shared_mutex>(shared_mutex));
  for (int i = 0; i < k_ - 1; ++i) {
    NodeId node_id = GenerateUniqueRandomId(holder_id_, 507);
    Contact contact = ComposeContact(node_id, 5333);
    AddContact(contact);
  }
  {
    RankInfoPtr rank_info;
    NodeId node_id = GenerateUniqueRandomId(holder_id_, 507);
    Contact contact = ComposeContact(node_id, 5337);
    int result = routing_table_.ForceKAcceptNewPeer(contact, 0, rank_info,
                                                    upgrade_lock);
    EXPECT_EQ(kNotInBrotherBucket, result);
    AddContact(contact);
  }
  int retry(0);
  if (k_ > 2) {
    for (int i = 0; i < k_; ++i) {
      NodeId node_id = GenerateUniqueRandomId(holder_id_, 508);
      Contact contact = ComposeContact(node_id, 5333);
      AddContact(contact);
    }
    for (int i = 0; i < k_; ++i) {
      NodeId node_id = GenerateUniqueRandomId(holder_id_, 506);
      Contact contact = ComposeContact(node_id, 5333);
      AddContact(contact);
    }

    // remove contact from bucket with common_leading_bit(507, 506)
    for (int i = 0; i < k_ - (k_ / 2 - 2); ++i) {
      auto pit_2 = routing_table_.contacts_.get<KBucketTag>().equal_range(4);
      routing_table_.SetValidated((*pit_2.first).node_id, false);
      pit_2 = routing_table_.contacts_.get<KBucketTag>().equal_range(5);
      routing_table_.SetValidated((*pit_2.first).node_id, false);
    }
    // Adding contact to bucket having kclosest contact
    bool fail_check(false);
    bool pass_check(false);
    while (retry < 1000) {
      NodeId node_id = GenerateUniqueRandomId(holder_id_, 508);
      Contact contact = ComposeContact(node_id, 5678);
      RankInfoPtr rank_info;
      auto pit =
          routing_table_.contacts_.get<KBucketDistanceToThisIdTag>().equal_range
          (boost::make_tuple(3));
      auto it_end = pit.second;
      --it_end;
      NodeId furthest_distance = (*it_end).distance_to_this_id;
      NodeId distance_to_node = routing_table_.kThisId_ ^ node_id;
      if (distance_to_node >= furthest_distance) {
        int force_result = routing_table_.ForceKAcceptNewPeer(contact, 3,
                              rank_info, upgrade_lock);
        EXPECT_EQ(kOutwithClosest, force_result);
        fail_check = true;
      } else {
        int force_result = routing_table_.ForceKAcceptNewPeer(contact, 3,
                              rank_info, upgrade_lock);
        EXPECT_EQ(kSuccess, force_result);
        pass_check = true;
      }
      if (fail_check && pass_check)
        break;
      ++retry;
    }
    EXPECT_EQ(k_, routing_table_.contacts_.get<KBucketTag>().count(3));
  }
  Clear();
  for (int i = 0; i < k_; ++i) {
    NodeId node_id = GenerateUniqueRandomId(holder_id_, 510);
    Contact contact = ComposeContact(node_id, 5333);
    AddContact(contact);
  }
  for (int i = 0; i < k_; ++i) {
    NodeId node_id = GenerateUniqueRandomId(holder_id_, 511);
    Contact contact = ComposeContact(node_id, 5333);
    AddContact(contact);
  }
  {
    EXPECT_EQ(2U, GetKBucketCount());
    EXPECT_EQ(k_ * 2, GetSize());
    NodeId node_id = GenerateUniqueRandomId(holder_id_, 511);
    Contact contact = ComposeContact(node_id, 5678);
    RankInfoPtr rank_info;
    int force_result = routing_table_.ForceKAcceptNewPeer(contact, 0, rank_info,
                                                          upgrade_lock);
    EXPECT_EQ(kOutwithClosest, force_result);
  }
  // When new contact not exist in brother_bucket

  for (int i = 0; i < (k_ - 1); ++i) {
    NodeId node_id = GenerateUniqueRandomId(holder_id_, 509);
    Contact contact = ComposeContact(node_id, 5333);
    AddContact(contact);
  }
  {
    EXPECT_EQ(3U, GetKBucketCount());
    EXPECT_EQ(k_ * 2 + (k_ - 1), GetSize());
    NodeId node_id = GenerateUniqueRandomId(holder_id_, 511);
    Contact contact = ComposeContact(node_id, 5678);
    RankInfoPtr rank_info;
    int force_result = routing_table_.ForceKAcceptNewPeer(contact, 0, rank_info,
                                                          upgrade_lock);
    EXPECT_EQ(kNotInBrotherBucket, force_result);
  }

  retry = 0;
  while (retry < 10000) {
    // Adding new contact to brother bucket
    NodeId node_id = GenerateUniqueRandomId(holder_id_, 510);
    Contact contact = ComposeContact(node_id, 5678);
    RankInfoPtr rank_info;
    auto pit =
        routing_table_.contacts_.get<KBucketDistanceToThisIdTag>().equal_range(
        boost::make_tuple(1));
    auto it_end = pit.second;
    --it_end;
    NodeId furthest_distance = (*it_end).distance_to_this_id;
    NodeId distance_to_node = routing_table_.kThisId_ ^ node_id;
    if (distance_to_node >= furthest_distance) {
      int force_result = routing_table_.ForceKAcceptNewPeer(contact, 1,
                            rank_info, upgrade_lock);
      EXPECT_EQ(kOutwithClosest, force_result);
    } else {
      int force_result = routing_table_.ForceKAcceptNewPeer(contact, 1,
                            rank_info, upgrade_lock);
      EXPECT_EQ(kSuccess, force_result);
    }
    ++retry;
  }
}

TEST_P(RoutingTableTest, BEH_AddContact) {
  {
    // try to add the holder itself into the routing table
    Contact contact = ComposeContact(holder_id_, 5000);
    AddContact(contact);
    EXPECT_EQ(0U, GetSize());
    EXPECT_EQ(1U, GetKBucketCount());
    EXPECT_EQ(0U, GetKBucketSizeForKey(0));
  }
  {
    // Test update NumFailedRpc and LastSeen when new contact already exists
    NodeId contact_id = GenerateUniqueRandomId(holder_id_, 508);
    Contact contact = ComposeContact(contact_id, 5000);
    AddContact(contact);
    routing_table_.IncrementFailedRpcCount(contact_id);
    bptime::ptime old_last_seen = (*(GetContainer().get<NodeIdTag>().find(
        contact_.node_id()))).last_seen;
    ASSERT_EQ(1U, (*(GetContainer().get<NodeIdTag>().find(
        contact_id))).num_failed_rpcs);
    AddContact(contact);
    ASSERT_EQ(0U, (*(GetContainer().get<NodeIdTag>().find(
        contact_id))).num_failed_rpcs);
    ASSERT_NE(old_last_seen, (*(GetContainer().get<NodeIdTag>().find(
        contact_id))).last_seen);
  }
  Clear();
  uint16_t i(0);
  {
    // create a list contacts having 3 common leading bits with the holder
    // and add them into the routing table
    for (; i < k_; ++i) {
      EXPECT_EQ(i, GetSize());
      EXPECT_EQ(1U, GetKBucketCount());
      NodeId contact_id = GenerateUniqueRandomId(holder_id_, 508);
      Contact contact = ComposeContact(contact_id, (5000 + i));
      AddContact(contact);
    }
    EXPECT_EQ(k_, GetKBucketSizeForKey(0));
  }

  {
    // Test Split Bucket
    // create a contact having 1 common leading bits with the holder
    // and add it into the routing table
    NodeId contact_id = GenerateUniqueRandomId(holder_id_, 510);
    Contact contact = ComposeContact(contact_id, 5000 + i);
    AddContact(contact);
    ++i;
    EXPECT_EQ(i, GetSize());

    // all 16 contacts having 3 common leading bits sit in the kbucket
    // covering 2-512
    EXPECT_EQ(3U, GetKBucketCount());
    EXPECT_EQ(0U, GetKBucketSizeForKey(0));
    EXPECT_EQ(1U, GetKBucketSizeForKey(1));
    EXPECT_EQ(k_, GetKBucketSizeForKey(2));
  }

  {
    // Test Split Bucket Advanced
    // create a contact having 4 common leading bits with the holder
    // and add it into the routing table
    NodeId contact_id = GenerateUniqueRandomId(holder_id_, 507);
    Contact contact = ComposeContact(contact_id, 5000 + i);
    AddContact(contact);
    ++i;
    EXPECT_EQ(i, GetSize());
    // all 16 contacts having 3 common leading bits sit in the kbucket
    // covering 3-3 now
    // an additonal kbucket covering 2-2 is now created
    EXPECT_EQ(5U, GetKBucketCount());
    EXPECT_EQ(0U, GetKBucketSizeForKey(0));
    EXPECT_EQ(1U, GetKBucketSizeForKey(1));
    EXPECT_EQ(0U, GetKBucketSizeForKey(2));
    EXPECT_EQ(k_, GetKBucketSizeForKey(3));
    EXPECT_EQ(1U, GetKBucketSizeForKey(4));
  }

  {
    // Test ForceK, reject and accept will be tested
    // create a contact having 3 common leading bits with the holder
    // and add it into the routing table
    // this contact shall be now attempting to add into the brother buckets
    // it shall be added (replace a previous one) if close enough or be rejected
    bool replaced(false);
    bool not_replaced(false);
    // To prevent test hanging
    uint16_t times_of_try(0);
    while (((!not_replaced) || (!replaced)) && (times_of_try < 60000)) {
      NodeId contact_id = GenerateUniqueRandomId(holder_id_, 508);
      Contact contact = ComposeContact(contact_id, (5000 + i + times_of_try));
      AddContact(contact);
      EXPECT_EQ(i, GetSize());
      EXPECT_EQ(5U, GetKBucketCount());

      Contact result;
      routing_table_.GetContact(contact_id, &result);
      // Make sure both replace and reject situation covered in ForceK sim test
      if (result != Contact()) {
        replaced = true;
      } else {
        not_replaced = true;
      }
      ++times_of_try;
    }
    ASSERT_GT(60000, times_of_try);
  }
}

TEST_P(RoutingTableSingleKTest, FUNC_AddContactPerformanceMaxFullFill) {
  // the last four common bits will not split kbucket
  for (int common_head = 0; common_head < 500; ++common_head) {
    for (int num_contact = 0; num_contact < k_; ++num_contact) {
      NodeId contact_id = GenerateUniqueRandomId(holder_id_, 511 - common_head);
      Contact contact = ComposeContact(contact_id, 5000);
      AddContact(contact);
    }
    EXPECT_EQ(((common_head + 1) * k_), GetSize());
    EXPECT_EQ((common_head + 1), GetKBucketCount());
  }
}

TEST_P(RoutingTableSingleKTest, FUNC_AddContactPerformance8000RandomFill) {
  for (int num_contact = 0; num_contact < 8000; ++num_contact) {
    NodeId contact_id(NodeId::kRandomId);
    Contact contact = ComposeContact(contact_id, 5000);
    AddContact(contact);

    uint32_t contacts_in_table(0);
    for (uint16_t i = 0; i < GetKBucketCount(); ++i) {
      uint32_t contacts_in_bucket = GetKBucketSizeForKey(i);
      ASSERT_GE(k_, contacts_in_bucket);
      contacts_in_table += contacts_in_bucket;
    }
    EXPECT_EQ(contacts_in_table, GetSize());
  }
}

TEST_P(RoutingTableTest, BEH_GetCloseContacts) {
  NodeId target_id = GenerateUniqueRandomId(holder_id_, 500);
  {
    // try to get close contacts from an empty routing table
    std::vector<Contact> close_contacts;
    std::vector<Contact> exclude_contacts;
    routing_table_.GetCloseContacts(target_id, 1, exclude_contacts,
                                    &close_contacts);
    EXPECT_EQ(0U, close_contacts.size());
  }
  {
    // try to get k close contacts from an k/2+1 filled routing table
    // with one un-validated contact
    for (int num_contact = 0; num_contact < (k_ / 2); ++num_contact) {
      NodeId contact_id(NodeId::kRandomId);
      Contact contact = ComposeContact(contact_id, 5000);
      AddContact(contact);
    }
    NodeId contact_id(NodeId::kRandomId);
    Contact contact = ComposeContact(contact_id, 5000);
    routing_table_.AddContact(contact, rank_info_);
    EXPECT_EQ(k_ / 2, GetSize());

    std::vector<Contact> close_contacts;
    std::vector<Contact> exclude_contacts;
    routing_table_.GetCloseContacts(target_id, k_, exclude_contacts,
                                    &close_contacts);
    EXPECT_EQ(k_ / 2, close_contacts.size());
  }
  Clear();
  {
    // try to get k close contacts from an k/2 filled routing table
    for (int num_contact = 0; num_contact < (k_ / 2); ++num_contact) {
      NodeId contact_id(NodeId::kRandomId);
      Contact contact = ComposeContact(contact_id, 5000);
      AddContact(contact);
    }
    EXPECT_EQ(k_ / 2, GetSize());

    std::vector<Contact> close_contacts;
    std::vector<Contact> exclude_contacts;
    routing_table_.GetCloseContacts(target_id, k_, exclude_contacts,
                                    &close_contacts);
    EXPECT_EQ(k_ / 2, close_contacts.size());
  }
  Clear();
  {
    // try to get k close contacts from a k+1 filled routing table
    for (int num_contact = 0; num_contact < (k_ - 1); ++num_contact) {
      NodeId contact_id = GenerateUniqueRandomId(holder_id_, 500);
      Contact contact = ComposeContact(contact_id, 5000);
      AddContact(contact);
    }
    NodeId contact_id_close = GenerateUniqueRandomId(holder_id_, 500);
    Contact contact_close = ComposeContact(contact_id_close, 5000);
    AddContact(contact_close);
    NodeId contact_id_furthest = GenerateUniqueRandomId(holder_id_, 501);
    Contact contact_furthest = ComposeContact(contact_id_furthest, 5000);
    AddContact(contact_furthest);
    EXPECT_EQ(k_ + 1, GetSize());

    std::vector<Contact> close_contacts;
    std::vector<Contact> exclude_contacts;
    routing_table_.GetCloseContacts(target_id, k_, exclude_contacts,
                                    &close_contacts);
    EXPECT_EQ(k_, close_contacts.size());
    ASSERT_NE(close_contacts.end(), std::find(close_contacts.begin(),
                                              close_contacts.end(),
                                              contact_close));
    ASSERT_EQ(close_contacts.end(), std::find(close_contacts.begin(),
                                              close_contacts.end(),
                                              contact_furthest));
  }
  Clear();
  {
    // try to get k close contacts from a k+1 filled routing table,
    // with one defined exception contact
    for (int num_contact = 0; num_contact < (k_ - 2); ++num_contact) {
      NodeId contact_id = GenerateUniqueRandomId(holder_id_, 500);
      Contact contact = ComposeContact(contact_id, 5000);
      AddContact(contact);
    }
    NodeId contact_id_close = GenerateUniqueRandomId(holder_id_, 500);
    Contact contact_close = ComposeContact(contact_id_close, 5000);
    AddContact(contact_close);
    NodeId contact_id_exclude = GenerateUniqueRandomId(holder_id_, 499);
    Contact contact_exclude = ComposeContact(contact_id_exclude, 5000);
    AddContact(contact_exclude);
    NodeId contact_id_furthest = GenerateUniqueRandomId(holder_id_, 501);
    Contact contact_furthest = ComposeContact(contact_id_furthest, 5000);
    AddContact(contact_furthest);
    EXPECT_EQ(k_ + 1, GetSize());

    std::vector<Contact> close_contacts;
    std::vector<Contact> exclude_contacts;
    exclude_contacts.push_back(contact_exclude);
    routing_table_.GetCloseContacts(target_id, k_, exclude_contacts,
                                    &close_contacts);
    EXPECT_EQ(k_, close_contacts.size());
    ASSERT_NE(close_contacts.end(), std::find(close_contacts.begin(),
                                              close_contacts.end(),
                                              contact_close));
    ASSERT_NE(close_contacts.end(), std::find(close_contacts.begin(),
                                              close_contacts.end(),
                                              contact_furthest));
    ASSERT_EQ(close_contacts.end(), std::find(close_contacts.begin(),
                                              close_contacts.end(),
                                              contact_exclude));
  }
  Clear();
  {
    // try to get k+21 close_contacts from a distributed filled routing_table
    // with one bucket contains k contacts having 111 common leading bits
    // and 16 buckets contains 2 contacts each, having 0-15 common leading bits

    // Initialize a routing table having the target to be the holder
    NodeId target_id = GenerateUniqueRandomId(holder_id_, 505);
    RoutingTableContactsContainer target_routingtable;

    for (int num_contact = 0; num_contact < k_; ++num_contact) {
      NodeId contact_id = GenerateUniqueRandomId(holder_id_, 400);
      Contact contact = ComposeContact(contact_id, 5000);
      AddContact(contact);
      RoutingTableContact new_contact(contact, target_id, 0);
      target_routingtable.insert(new_contact);
    }

    for (int common_head = 0; common_head < 16; ++common_head) {
      for (int num_contact = 0; num_contact < 2; ++num_contact) {
        NodeId contact_id = GenerateUniqueRandomId(holder_id_,
                                                   511 - common_head);
        Contact contact = ComposeContact(contact_id, 5000);
        AddContact(contact);
        RoutingTableContact new_contact(contact, target_id, 0);
        target_routingtable.insert(new_contact);
      }
    }
    EXPECT_EQ(k_ + (16 * 2), GetSize());
    EXPECT_EQ(17U, GetKBucketCount());
    EXPECT_EQ(k_ + (16 * 2), target_routingtable.size());

    std::vector<Contact> close_contacts;
    std::vector<Contact> exclude_contacts;
    // make sure the target_id in the exclude_contacts list
    exclude_contacts.push_back(ComposeContact(target_id, 5000));

    routing_table_.GetCloseContacts(target_id, k_ + 21,
                                               exclude_contacts,
                                               &close_contacts);
    EXPECT_EQ(k_ + 21, close_contacts.size());

    ContactsByDistanceToThisId key_dist_indx
      = target_routingtable.get<DistanceToThisIdTag>();
    uint32_t counter(0);
    auto it = key_dist_indx.begin();
    while ((counter < (k_ + 21u)) && (it != key_dist_indx.end())) {
      ASSERT_NE(close_contacts.end(), std::find(close_contacts.begin(),
                                                close_contacts.end(),
                                                (*it).contact));
      ++counter;
      ++it;
    }
  }
}

TEST_P(RoutingTableTest, BEH_SetPublicKey) {
  this->FillContactToRoutingTable();
  std::string new_public_key(RandomString(113));
  EXPECT_EQ(kFailedToFindContact,
            routing_table_.SetPublicKey(NodeId(NodeId::kRandomId),
                                        new_public_key));
  EXPECT_NE(new_public_key , (*(GetContainer().get<NodeIdTag>().find(
      contact_.node_id()))).public_key);
  ASSERT_EQ(0, routing_table_.SetPublicKey(contact_.node_id(),
                                           new_public_key));
  ASSERT_EQ(new_public_key , (*(GetContainer().get<NodeIdTag>().find(
      contact_.node_id()))).public_key);

  Clear();
  {
    // try to set un-validated contact's publickey
    NodeId contact_id(NodeId::kRandomId);
    Contact contact = ComposeContact(contact_id, 5000);
    routing_table_.AddContact(contact, rank_info_);
    EXPECT_EQ(kFailedToFindContact,
              routing_table_.SetPublicKey(contact_id, new_public_key));
  }
}

TEST_P(RoutingTableTest, BEH_UpdateRankInfo) {
  this->FillContactToRoutingTable();
  RankInfoPtr new_rank_info(new(transport::Info));
  new_rank_info->rtt = 13313;
  EXPECT_EQ(kFailedToFindContact,
            routing_table_.UpdateRankInfo(NodeId(NodeId::kRandomId),
                                          new_rank_info));
  ASSERT_EQ(0, routing_table_.UpdateRankInfo(contact_.node_id(),
                                             new_rank_info));
  ASSERT_EQ(new_rank_info->rtt, (*(GetContainer().get<NodeIdTag>().find(
      contact_.node_id()))).rank_info->rtt);

  Clear();
  {
    // try to update un-validated contact's rankinfo
    NodeId contact_id(NodeId::kRandomId);
    Contact contact = ComposeContact(contact_id, 5000);
    routing_table_.AddContact(contact, rank_info_);
    EXPECT_EQ(kFailedToFindContact,
              routing_table_.UpdateRankInfo(contact_id, new_rank_info));
  }
}

TEST_P(RoutingTableTest, BEH_SetPreferredEndpoint) {
  this->FillContactToRoutingTable();
  IP ip = IP::from_string("127.0.0.1");
  EXPECT_EQ(kFailedToFindContact,
            routing_table_.SetPreferredEndpoint(NodeId(NodeId::kRandomId), ip));
  ASSERT_EQ(0, routing_table_.SetPreferredEndpoint(contact_.node_id(), ip));
  ASSERT_EQ(ip, (*(GetContainer().get<NodeIdTag>().find(
    contact_.node_id()))).contact.PreferredEndpoint().ip);

  Clear();
  {
    // try to set an un-validated contact's preferredendpoint
    NodeId contact_id(NodeId::kRandomId);
    Contact contact = ComposeContact(contact_id, 5000);
    routing_table_.AddContact(contact, rank_info_);
    EXPECT_EQ(kFailedToFindContact,
              routing_table_.SetPreferredEndpoint(contact_id, ip));
  }
}

TEST_P(RoutingTableTest, BEH_IncrementFailedRpcCount) {
  this->FillContactToRoutingTable();
  EXPECT_EQ(kFailedToFindContact, routing_table_.IncrementFailedRpcCount(
      NodeId(NodeId::kRandomId)));
  EXPECT_EQ(uint16_t(0), (*(GetContainer().get<NodeIdTag>().find(
     contact_.node_id()))).num_failed_rpcs);
  ASSERT_EQ(kSuccess,
            routing_table_.IncrementFailedRpcCount(contact_.node_id()));
  ASSERT_EQ(1, (*(GetContainer().get<NodeIdTag>().find(
               contact_.node_id()))).num_failed_rpcs);
  {
    // keep increasing one contact's failed RPC counter
    // till it gets removed
    size_t ori_size = GetSize();
    uint16_t times_of_try = 0;
    do {
      ++times_of_try;
    } while ((routing_table_.IncrementFailedRpcCount(contact_.node_id()) ==
              kSuccess) && (times_of_try <= (kFailedRpcTolerance + 5)));
    // prevent deadlock
    if (times_of_try == (kFailedRpcTolerance + 5)) {
      FAIL();
    } else {
      ASSERT_EQ(ori_size-1, GetSize());
    }
  }
  Clear();
  {
    // try to increase failed RPC counter of an un-validated contact
    NodeId contact_id(NodeId::kRandomId);
    Contact contact = ComposeContact(contact_id, 5000);
    routing_table_.AddContact(contact, rank_info_);
    EXPECT_EQ(kFailedToFindContact,
              routing_table_.IncrementFailedRpcCount(contact_id));
  }
}

TEST_P(RoutingTableTest, BEH_GetBootstrapContacts) {
  {
    this->FillContactToRoutingTable();
    std::vector<Contact> contacts;
    routing_table_.GetBootstrapContacts(&contacts);
    EXPECT_EQ(k_, contacts.size());
    EXPECT_EQ(contact_.node_id(),
        (std::find(contacts.begin(), contacts.end(), contact_))->node_id());
  }
  Clear();
  {
    for (int num_contact = 0; num_contact < (k_ / 2); ++num_contact) {
      NodeId contact_id(NodeId::kRandomId);
      Contact contact = ComposeContact(contact_id, 5000);
      AddContact(contact);
    }
    NodeId contact_id(NodeId::kRandomId);
    Contact contact = ComposeContact(contact_id, 5000);
    routing_table_.AddContact(contact, rank_info_);
    std::vector<Contact> contacts;
    routing_table_.GetBootstrapContacts(&contacts);
    EXPECT_EQ(k_ / 2, contacts.size());
  }
}

TEST_P(RoutingTableTest, BEH_GetAllContacts) {
  {
    std::vector<Contact> contacts;
    routing_table_.GetAllContacts(&contacts);
    EXPECT_TRUE(contacts.empty());
  }
  {
    this->FillContactToRoutingTable();
    std::vector<Contact> contacts;
    routing_table_.GetAllContacts(&contacts);
    EXPECT_EQ(k_, contacts.size());
    EXPECT_EQ(contact_.node_id(),
        (std::find(contacts.begin(), contacts.end(), contact_))->node_id());
  }
}

TEST_P(RoutingTableTest, BEH_GetLocalRankInfo) {
  {
    NodeId contact_id(NodeId::kRandomId);
    Contact contact = ComposeContact(contact_id, 5000);
    EXPECT_EQ(RankInfoPtr(), routing_table_.GetLocalRankInfo(contact));
  }
  {
    for (int num_contact = 0; num_contact < (k_ / 2); ++num_contact) {
      NodeId contact_id(NodeId::kRandomId);
      Contact contact = ComposeContact(contact_id, 5000);
      AddContact(contact);
    }
    NodeId contact_id(NodeId::kRandomId);
    Contact contact = ComposeContact(contact_id, 5000);
    RankInfoPtr new_rank_info(new(transport::Info));
    new_rank_info->rtt = 13313;
    routing_table_.AddContact(contact, new_rank_info);
    routing_table_.SetValidated(contact.node_id(), true);
    EXPECT_EQ(new_rank_info->rtt,
              routing_table_.GetLocalRankInfo(contact)->rtt);
  }
}

TEST_P(RoutingTableSingleKTest, BEH_MutexTestWithMultipleThread) {
  const size_t kNumberOfThreads(10);
  const uint16_t kIterartorSize(10);
  std::vector<NodeId> node_ids_stored, node_ids_to_be_stored;
  std::vector<NodeId> node_ids_stored_then_deleted;
  std::vector<boost::tuple<std::string, RankInfoPtr, IP>> stored_attrs;
  std::set <NodeId> unique_node_ids;
  bool unique(false);
  for (uint16_t i = 0; i < kIterartorSize; ++i) {
    // Node ids stored
    {
      NodeId node_id;
      do {
        auto it = unique_node_ids.insert(GenerateUniqueRandomId(holder_id_,
                                         510 - i));
        unique = it.second;
        if (unique)
          node_id = *(it.first);
      } while (!unique);
      Contact contact = ComposeContact(node_id, 5001 + i);
      AddContact(contact);
      node_ids_stored.push_back(node_id);
    }
    // Node ids to be stored
    {
      NodeId node_id;
      do {
        auto it = unique_node_ids.insert(GenerateUniqueRandomId(holder_id_,
                                                                510 - i));
        unique = it.second;
        if (unique)
          node_id = (*it.first);
      } while (!unique);
      Contact contact = ComposeContact(node_id, 5001 + (i + kIterartorSize));
      node_ids_to_be_stored.push_back(node_id);
    }
    // Node ids stored then deleted
    {
      NodeId node_id;
      do {
        auto it = unique_node_ids.insert(
                      GenerateUniqueRandomId(holder_id_,
                                             510 - (i + kIterartorSize)));
        unique = it.second;
        if (unique)
          node_id = (*it.first);
      } while (!unique);
      Contact contact = ComposeContact(node_id,
                                       5001 + (i + 2 * kIterartorSize));
      node_ids_stored_then_deleted.push_back(node_id);
    }
    // Constructing attributes vector
    std::string public_key(RandomString(113));
    RankInfoPtr new_rank_info(new(transport::Info));
    new_rank_info->rtt = 13313 + i;
    IP ip = IP::from_string("127.0.0.1");
    stored_attrs.push_back(boost::make_tuple(public_key, new_rank_info, ip));
  }
  EXPECT_EQ(node_ids_stored.size(), GetSize());
  // Posting all the jobs
  AsioService asio_service;
  for (uint16_t i = 0; i < kIterartorSize; ++i) {
    Contact contact = ComposeContact(node_ids_to_be_stored[i], 6001 + i);
    asio_service.service().post(
        std::bind(&RoutingTableSingleKTest::DoAddContact, this, contact));
    asio_service.service().post(
        std::bind(&RoutingTableSingleKTest::DoGetContact, this,
                  node_ids_stored[i]));
    asio_service.service().post(
        std::bind(&RoutingTableSingleKTest::DoGetCloseContacts, this, 10));
    asio_service.service().post(
        std::bind(&RoutingTableSingleKTest::DoSetPublicKey, this,
                  node_ids_stored[i], stored_attrs[i].get<0>()));
    asio_service.service().post(
        std::bind(&RoutingTableSingleKTest::DoUpdateRankInfo, this,
                  node_ids_stored[i], stored_attrs[i].get<1>()));
    asio_service.service().post(
        std::bind(&RoutingTableSingleKTest::DoSetPreferredEndpoint, this,
                  node_ids_stored[i], stored_attrs[i].get<2>()));
    // Add and then remove contacts using IncrementFailedRpcCount()
    Contact contact_1 = ComposeContact(node_ids_stored_then_deleted[i],
                                       7001 + i);
    asio_service.service().post(
        std::bind(&RoutingTableSingleKTest::DoAddRemoveContact, this,
                  contact_1));
  }
  // Running the threads
  asio_service.Start(kNumberOfThreads);
  node_ids_stored.insert(node_ids_stored.end(), node_ids_to_be_stored.begin(),
                         node_ids_to_be_stored.end());
  int count(0), attempts(1000);
  while ((node_ids_stored.size() != GetSize()) && (count++ != attempts))
    Sleep(boost::posix_time::milliseconds(1));
  asio_service.Stop();
  // Verifying results
  ASSERT_EQ(node_ids_stored.size(), GetSize());
  for (uint16_t i = 0; i < node_ids_stored.size(); ++i) {
    Contact result;
    routing_table_.GetContact(node_ids_stored[i], &result);
    EXPECT_EQ(node_ids_stored[i], result.node_id());
  }
  // Checking changed attributes
  for (int i = 0; i < kIterartorSize; ++i) {
    EXPECT_EQ(stored_attrs[i].get<0>(),
              (*(GetContainer().get<NodeIdTag>().find(node_ids_stored[i]))).
                  public_key);
    EXPECT_EQ(stored_attrs[i].get<1>()->rtt,
              (*(GetContainer().get<NodeIdTag>().find(node_ids_stored[i]))).
                  rank_info->rtt);
    EXPECT_EQ(stored_attrs[i].get<2>(),
              (*(GetContainer().get<NodeIdTag>().find(node_ids_stored[i]))).
                  contact.PreferredEndpoint().ip);
  }
}

}  // namespace test

}  // namespace dht

}  // namespace maidsafe
