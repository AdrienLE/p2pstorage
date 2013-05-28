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
    Jellyfish(JellyfishConfig const &config) : _jelly_conf(config), _logged_in(false) {}
    
    JellyfishReturnCode login(std::string const &login, std::string const &password);
    
    std::string const &login() const { return _login; }
    
    struct UserData
    {
        std::string salt;
        uint32_t pin;
        std::string public_key;
        std::string private_key;
        
        template<class Archive>
        void serialize(Archive & ar, const unsigned int version)
        {
            ar & salt;
            ar & pin;
            ar & public_key;
            ar & private_key;
        }
    };
    
protected:
    JellyfishConfig _jelly_conf;
    
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
        Synchronizer(Type &ret) : _ret(ret), _mutex(new boost::mutex), _lock(new boost::mutex::scoped_lock(*_mutex)), _cond_var(new boost::condition_variable)
        {}
        void operator()(Type value)
        {
            _ret = value;
        }
        void wait()
        {
            _cond_var->wait(*_lock);
        }
    private:
        Type &_ret;
        std::shared_ptr<boost::mutex> _mutex;
        std::shared_ptr<boost::mutex::scoped_lock> _lock;
        std::shared_ptr<boost::condition_variable> _cond_var;
    };
};
