#pragma once

#include "JellyfishNode.h"
#include "JellyfishConfig.h"
#include "jellutils/enum.h"
#include "jellutils/serialize_cast.h"

MAKE_ENUM(JellyfishReturnCode,
	(jSuccess)
	(jNoSuchUser)
	(jBadPassword))

namespace mk = maidsafe::dht;

void PrintNodeInfo(const mk::Contact &contact);

// This class is synchronous but should be thread safe as well.
class Jellyfish
{
public:
  Jellyfish(JellyfishConfig const &config) : _jelly_config(config), _logged_in(false) {}

  JellyfishReturnCode login(std::string const &login, std::string const &password);

protected:
  JellyfishConfig _jelly_config;

  typedef mk::NodeContainer<JellyfishNode> JellyNode;
  typedef std::shared_ptr<JellyNode> JellyNodePtr;

  JellyNodePtr _jelly_node;
  mk::KeyPairPtr _keys;
  std::string _login;
  bool _logged_in;

  enum Table
  {
  	tUser
  };

  maidsafe::dht::Key getKey(Table table, std::string const &key);
  std::string getNodeIdUser(std::string login);

  template<class Type>
  class Synchronizer
  {
  public:
  	Synchronizer(Type &ret) : _ret(ret), _mutex(), _lock(_mutex), _cond_var()
  	{}
  	void operator()(Type value)
  	{
  	  _ret = value;
  	}
  	void wait()
  	{
  	  _cond_var.wait(_lock);
  	}
  private:
  	Type &_ret;
    boost::mutex _mutex;
    boost::mutex::scoped_lock _lock;
  	boost::condition_variable _cond_var;
  };
};
