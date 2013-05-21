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

#ifndef MAIDSAFE_DHT_UTILS_H_
#define MAIDSAFE_DHT_UTILS_H_

#include <string>
#include <vector>

#include "maidsafe/common/rsa.h"

namespace maidsafe {

namespace transport { struct Endpoint; }

namespace dht {

class Contact;
class NodeId;

namespace protobuf { class Contact; }

bool HasId(const Contact &contact, const NodeId &node_id);

Contact FromProtobuf(const protobuf::Contact &protobuf_contact);

protobuf::Contact ToProtobuf(const Contact &contact);

bool IsListeningOnTCP(const Contact &contact);

// sort the contacts according the distance to the target key
void SortContacts(const NodeId &target_key, std::vector<Contact> *contacts);

void StubContactValidationGetter(
    asymm::Identity identity,
    asymm::GetPublicKeyAndValidationCallback callback);

bool StubContactValidator(asymm::Identity identity,
                          asymm::PublicKey public_key,
                          asymm::ValidationToken validation_token);

bool StubValidate(const asymm::PlainText &plain_text,
                  const asymm::Signature &signature,
                  const asymm::PublicKey &public_key);

}  // namespace dht

}  // namespace maidsafe

#endif  // MAIDSAFE_DHT_UTILS_H_
