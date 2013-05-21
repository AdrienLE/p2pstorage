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

#ifndef MAIDSAFE_DHT_VERSION_H_
#define MAIDSAFE_DHT_VERSION_H_

#define MAIDSAFE_DHT_VERSION 3200

#if defined CMAKE_MAIDSAFE_DHT_VERSION &&\
            MAIDSAFE_DHT_VERSION != CMAKE_MAIDSAFE_DHT_VERSION
#  error The project version has changed.  Re-run CMake.
#endif

#include "maidsafe/common/version.h"
#include "maidsafe/transport/version.h"

#define THIS_NEEDS_MAIDSAFE_COMMON_VERSION 1100
#if MAIDSAFE_COMMON_VERSION < THIS_NEEDS_MAIDSAFE_COMMON_VERSION
#  error This API is not compatible with the installed library.\
    Please update the maidsafe-common library.
#elif MAIDSAFE_COMMON_VERSION > THIS_NEEDS_MAIDSAFE_COMMON_VERSION
#  error This API uses a newer version of the maidsafe-common library.\
    Please update this project.
#endif

#define THIS_NEEDS_MAIDSAFE_TRANSPORT_VERSION 200
#if MAIDSAFE_TRANSPORT_VERSION < THIS_NEEDS_MAIDSAFE_TRANSPORT_VERSION
#  error This API is not compatible with the installed library.\
    Please update the maidsafe-transport library.
#elif MAIDSAFE_TRANSPORT_VERSION > THIS_NEEDS_MAIDSAFE_TRANSPORT_VERSION
#  error This API uses a newer version of the maidsafe-transport library.\
    Please update this project.
#endif

#endif  // MAIDSAFE_DHT_VERSION_H_
