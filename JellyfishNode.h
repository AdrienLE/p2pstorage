#pragma once

#include "maidsafe/dht/config.h"
#include "maidsafe/dht/node-api.h"
#include "maidsafe/dht/node_container.h"
#include "maidsafe/common/crypto.h"

#define JELLYFISH_VERSION "0.1"

class JellyfishNode : public maidsafe::dht::Node
{
public:
  JellyfishNode(boost::asio::io_service &asio_service,                 // NOLINT (Fraser)
       maidsafe::dht::TransportPtr listening_transport,
       maidsafe::dht::MessageHandlerPtr message_handler,
       maidsafe::dht::KeyPairPtr default_key_pair,
       bool client_only_node,
       const uint16_t &k,
       const uint16_t &alpha,
       const uint16_t &beta,
       const boost::posix_time::time_duration &mean_refresh_interval)
    : maidsafe::dht::Node(asio_service, listening_transport, message_handler, default_key_pair,
      client_only_node, k, alpha, beta, mean_refresh_interval) {}

  virtual ~JellyfishNode() {}
};
