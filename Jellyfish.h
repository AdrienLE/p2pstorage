#pragma once

#include "JellyfishNode.h"
#include "JellyfishConfig.h"

void PrintNodeInfo(const Contact &contact);

class Jellyfish
{
public:
  Jellyfish(JellyfishConfig const &config) : _jelly_config(config) {}

private:
  JellyfishConfig _jelly_config;

  typedef NodeContainer<JellyfishNode> JellyNode;
  typedef std::shared_ptr<NodeContainer<JellyfishNode>> JellyNodePtr;
};
