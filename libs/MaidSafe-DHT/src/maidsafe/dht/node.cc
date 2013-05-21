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

#include "maidsafe/dht/node-api.h"
#include "maidsafe/dht/node_impl.h"
#include "maidsafe/dht/contact.h"

namespace maidsafe {

namespace dht {

Node::Node(boost::asio::io_service &asio_service,             // NOLINT (Fraser)
           TransportPtr listening_transport,
           MessageHandlerPtr message_handler,
           KeyPairPtr default_key_pair,
           bool client_only_node,
           const uint16_t &k,
           const uint16_t &alpha,
           const uint16_t &beta,
           const boost::posix_time::time_duration &mean_refresh_interval)
    : pimpl_(new NodeImpl(asio_service, listening_transport, message_handler,
                          default_key_pair, client_only_node, k, alpha, beta,
                          mean_refresh_interval)) {}

Node::~Node() {}

void Node::Join(const NodeId &node_id,
                std::vector<Contact> bootstrap_contacts,
                JoinFunctor callback) {
  pimpl_->Join(node_id, bootstrap_contacts, callback);
}

void Node::Leave(std::vector<Contact> *bootstrap_contacts) {
  pimpl_->Leave(bootstrap_contacts);
}

void Node::Store(const Key &key,
                 const std::string &value,
                 const std::string &signature,
                 const boost::posix_time::time_duration &ttl,
                 PrivateKeyPtr private_key,
                 StoreFunctor callback) {
  pimpl_->Store(key, value, signature, ttl, private_key, callback);
}

void Node::Delete(const Key &key,
                 const std::string &value,
                 const std::string &signature,
                 PrivateKeyPtr private_key,
                 DeleteFunctor callback) {
  pimpl_->Delete(key, value, signature, private_key, callback);
}

void Node::Update(const Key &key,
                  const std::string &new_value,
                  const std::string &new_signature,
                  const std::string &old_value,
                  const std::string &old_signature,
                  const boost::posix_time::time_duration &ttl,
                  PrivateKeyPtr private_key,
                  UpdateFunctor callback) {
  pimpl_->Update(key, new_value, new_signature, old_value, old_signature,
                 ttl, private_key, callback);
}

void Node::FindValue(const Key &key,
                     PrivateKeyPtr private_key,
                     FindValueFunctor callback,
                     const uint16_t &extra_contacts,
                     bool cache) {
  pimpl_->FindValue(key, private_key, callback, extra_contacts, cache);
}

void Node::FindNodes(const Key &key,
                     FindNodesFunctor callback,
                     const uint16_t &extra_contacts) {
  pimpl_->FindNodes(key, callback, extra_contacts);
}

void Node::GetContact(const NodeId &node_id, GetContactFunctor callback) {
  pimpl_->GetContact(node_id, callback);
}

void Node::SetContactValidationGetter(
    asymm::GetPublicKeyAndValidationFunctor contact_validation_getter) {
  pimpl_->SetContactValidationGetter(contact_validation_getter);
}

void Node::SetContactValidator(
    asymm::ValidatePublicKeyFunctor contact_validator) {
  pimpl_->SetContactValidator(contact_validator);
}

void Node::SetValidate(asymm::ValidateFunctor validate_functor) {
  pimpl_->SetValidate(validate_functor);
}

void Node::SetLastSeenToNow(const Contact &contact) {
  pimpl_->SetLastSeenToNow(contact);
}

void Node::IncrementFailedRpcs(const Contact &contact) {
  pimpl_->IncrementFailedRpcs(contact);
}

void Node::UpdateRankInfo(const Contact &contact, RankInfoPtr rank_info) {
  pimpl_->UpdateRankInfo(contact, rank_info);
}

RankInfoPtr Node::GetLocalRankInfo(const Contact &contact) {
  return pimpl_->GetLocalRankInfo(contact);
}

void Node::GetAllContacts(std::vector<Contact> *contacts) {
  pimpl_->GetAllContacts(contacts);
}

void Node::GetBootstrapContacts(std::vector<Contact> *contacts) {
  pimpl_->GetBootstrapContacts(contacts);
}

void Node::Ping(const Contact &contact, PingFunctor callback) {
  pimpl_->Ping(contact, callback);
}

void Node::set_check_cache_functor(
    const CheckCacheFunctor &check_cache_functor) {
  pimpl_->set_check_cache_functor(check_cache_functor);
}

Contact Node::contact() const {
  return pimpl_->contact();
}

bool Node::joined() const {
  return pimpl_->joined();
}

OnOnlineStatusChangePtr Node::on_online_status_change() {
  return pimpl_->on_online_status_change();
}

bool Node::client_only_node() const {
  return pimpl_->client_only_node();
}

uint16_t Node::k() const {
  return pimpl_->k();
}

}  // namespace dht

}  // namespace maidsafe
