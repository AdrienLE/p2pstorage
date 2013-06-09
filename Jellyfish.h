#pragma once

#include "thrift/server/TThreadPoolServer.h"
#include "maidsafe/common/utils.h"
#include "maidsafe/common/log.h"
#include "JellyfishNode.h"
#include "JellyfishConfig.h"
#include "jellutils/enum.h"
#include "jellutils/serialize_cast.h"
#include "gen-cpp/JellyInternal.h"
#include "gen-cpp/jellyinternal_types.h"

class JellyfishInternal;

MAKE_ENUM(JellyfishReturnCode,
          (jSuccess)
          (jNoSuchUser)
          (jBadPassword)
          (jCouldNotStore)
          (jNotLoggedIn)
          (jFileSystemError)
          (jNoNodes)
          (jAddError)
          (jDisconnected)) // We should make it as unlikely as possible that this will occur.

namespace mk = maidsafe::dht;

void PrintNodeInfo(const mk::Contact &contact);

// This class is synchronous but should be thread safe as well.
class Jellyfish
{
public:
    Jellyfish(JellyfishConfig const &config) : _jelly_conf(config), _logged_in(false) {}
    
    JellyfishReturnCode login(std::string const &login, std::string const &password);
    JellyfishReturnCode createAccount(std::string const &login, std::string const &password);
    JellyfishReturnCode initStorage(std::string const &path, uint64_t size);
    JellyfishReturnCode addFile(std::string const &path);
    void runInitNode(boost::filesystem::path const &bootstrap_file_path);
    
    std::string const &login() const { return _login; }
    
    struct UserData
    {
        std::string salt;
        uint32_t pin;
        std::string public_key;
        std::string private_key;
        std::string aes256_key;
        
        template<class Archive>
        void serialize(Archive & ar, const unsigned int version)
        {
            ar & salt;
            ar & pin;
            ar & public_key;
            ar & private_key;
            ar & aes256_key;
        }
    };

    struct StorageData
    {
        StorageData() : size(0) {}
        uint64_t size;

        template<class Archive>
        void serialize(Archive & ar, const unsigned version)
        {
            ar & size;
        }
    };

    struct FileBlockInfo
    {
        std::string iv;
        std::string hash_id;
        std::string node_id; // Can be compressed by storing the first few bytes.

        template<class Archive>
        void serialize(Archive & ar, const unsigned version)
        {
            ar & iv;
            ar & hash_id;
            ar & node_id;
        }
    };

    struct StoredBlock
    {
        std::string file_id;
        std::string hash_id;
        uint32_t size;

        template<class Archive>
        void serialize(Archive & ar, const unsigned version)
        {
            ar & file_id;
            ar & hash_id;
            ar & size;
        }
    };

    struct File
    {
        std::string relative_path;
        std::string salt;
        std::string hash;
        uint64_t size;
        uint16_t real_parts;
        uint16_t code_parts;
        std::vector<FileBlockInfo> blocks;

        template<class Archive>
        void serialize(Archive & ar, const unsigned version)
        {
            ar & relative_path;
            ar & salt;
            ar & hash;
            ar & size;
            ar & real_parts;
            ar & code_parts;
            ar & blocks;
        }
    };

    JellyInternalStatus::type localPrepareAdd(std::string const &id, long long size, ClientProof const &client);
    JellyInternalStatus::type localAdd(std::string const &id, std::string const &file, ClientProof const &client);
    JellyInternalStatus::type localRemove(std::string const &id, ClientProof const &client);
    void hashPart(HashStatus &res, std::string const &id, std::string const &salt, ClientProof const &client);
    
    static void getPartsCodes(std::istream &content, uint64_t size, int n_parts, int n_codes, std::vector<std::ostream *> const &parts, std::vector<std::ostream *> const &codes);
    static bool getContentFromCodes(std::vector<std::istream *> in, std::vector<int> position, int n_parts, int n_codes, uint64_t size, std::ostream &out);

protected:
    JellyfishConfig _jelly_conf;
    
    typedef mk::NodeContainer<JellyfishNode> JellyNode;
    typedef std::shared_ptr<JellyNode> JellyNodePtr;
    
    JellyNodePtr _jelly_node;
    mk::KeyPairPtr _keys;
    mk::PrivateKeyPtr _private_key_ptr;
    std::string _login;
    UserData _user_data;
    StorageData _storage_data;
    std::string _storage_path;
    bool _logged_in;
    boost::shared_ptr<boost::thread> _server_thread;
    boost::shared_ptr<apache::thrift::server::TThreadPoolServer> _server;
    boost::mutex _wait_mutex;
    typedef boost::mutex::scoped_lock scoped_lock;
    
    MAKE_ENUM(Table,
        (tUser)
        (tFile)
        (tStorage)
        (tFileKey)
        (tClientParts)
        (tUserFiles))
    
    maidsafe::dht::Key getKey(Table table, std::string const &key);
    std::string getNodeIdUser(std::string login);
    void startServer();
    bool contactServer(maidsafe::dht::Contact const &contact, boost::function<bool (JellyInternalClient &)> fct, bool raise = false, bool log = false);
    
    template<class Type>
    class Synchronizer
    {
    public:
        Synchronizer(Type &ret) : _ret(ret), _mutex(new boost::mutex), _lock(new boost::mutex::scoped_lock(*_mutex)), _cond_var(new boost::condition_variable)
        {}
        void operator()(Type value)
        {
            _ret = value;
            _cond_var->notify_one();
        }
        void operator()(int res, Type value)
        {
            result = res;
            _ret = value;
            _cond_var->notify_one();
        }
        void wait()
        {
            _cond_var->wait(*_lock);
        }

        int result;
    private:
        Type &_ret;
        std::shared_ptr<boost::mutex> _mutex;
        std::shared_ptr<boost::mutex::scoped_lock> _lock;
        std::shared_ptr<boost::condition_variable> _cond_var;
    };
};
