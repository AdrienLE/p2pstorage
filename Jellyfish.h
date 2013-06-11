#pragma once

#include "JellyInclude.h"

#include "Schema.h"
#include "FilesStore.h"
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
          (jDisconnected) // We should make it as unlikely as possible that this will occur.
          (jFileNotFound)
          (jLsError)
          (jAlreadyInitialized))


#define W 15
#define OPTIMAL_PACKET_SIZE 4000
#define N_PARTS 5
#define N_CODES 5
#define THRESHOLD 100000
#define SALT_BYTES 16
#define UUID_BYTES (128/8)

namespace mk = maidsafe::dht;

void PrintNodeInfo(const mk::Contact &contact);

class FilesStore;

// This class is synchronous but should be thread safe as well.
class Jellyfish
{
public:
    Jellyfish(JellyfishConfig const &config) : _jelly_conf(config), _logged_in(false)
    {
    }
    ~Jellyfish()
    {
    }
    
    JellyfishReturnCode login(std::string const &login, std::string const &password);
    JellyfishReturnCode createAccount(std::string const &login, std::string const &password);
    JellyfishReturnCode initStorage(std::string const &path, uint64_t size);
    JellyfishReturnCode addFile(std::string const &path, std::string const &unique_name);
    JellyfishReturnCode getFile(std::string const &unique_name);
    template<class Container>
    JellyfishReturnCode listFiles(Container &cont)
    {
        maidsafe::dht::FindValueReturns findvalue;
        Synchronizer<maidsafe::dht::FindValueReturns> sync(findvalue);
        _jelly_node->node()->FindValue(getKey(tUserFiles, _login), _private_key_ptr, sync);
        sync.wait();
        if (sync.result != mk::kSuccess)
            return jLsError;
        for (auto const &v: findvalue.values_and_signatures)
            cont.insert(serialize_cast<AbbreviatedFile>(v.first));
        return jSuccess;
    }

    __attribute__((noreturn)) void runInitNode(boost::filesystem::path const &bootstrap_file_path);
    
    std::string const &login() const { return _login; }

    JellyInternalStatus::type localPrepareAdd(std::string const &id, long long size, ClientProof const &client);
    JellyInternalStatus::type localAdd(std::string const &salt, std::string const &id, std::string const &file, ClientProof const &client);
    JellyInternalStatus::type localRemove(std::string const &id, ClientProof const &client);
    void hashPart(HashStatus &res, std::string const &id, std::string const &salt, ClientProof const &client);
    
    static void getPartsCodes(std::istream &content, uint64_t size, int n_parts, int n_codes, std::vector<std::ostream *> const &parts, std::vector<std::ostream *> const &codes);
    static bool getContentFromCodes(std::vector<std::istream *> in, std::vector<int> position, int n_parts, int n_codes, uint64_t size, std::ostream &out);

    static uint64_t encodeFile(std::string const &iv, std::string const &key, const char *filename, std::vector<std::ostream *> const &parts, std::vector<std::ostream *> const &codes, boost::function<bool (uint64_t size)> big_callback, boost::function<bool (const char *, uint64_t)> small_callback);
    static bool decodeFile(std::string const &iv, std::string const &key, std::vector<std::istream *> const &in, std::vector<int> const &positions, uint64_t size, std::string const &filename_out);

protected:
    JellyfishConfig _jelly_conf;
    
    typedef mk::NodeContainer<JellyfishNode> JellyNode;
    typedef std::shared_ptr<JellyNode> JellyNodePtr;
    
    JellyNodePtr _jelly_node;
    mk::KeyPairPtr _keys;
    mk::PrivateKeyPtr _private_key_ptr;
    std::string _login;
    UserData _user_data;
    bool _logged_in;
    boost::shared_ptr<boost::thread> _server_thread;
    boost::shared_ptr<apache::thrift::server::TThreadPoolServer> _server;
    boost::mutex _wait_mutex;
    typedef boost::mutex::scoped_lock scoped_lock;

    boost::shared_ptr<FilesStore> _files_store;
    std::string _config_path;
    
    static maidsafe::dht::Key getKey(Table table, std::string const &key);
    std::string getNodeIdUser(std::string login);
    void startServer();
    bool contactServer(maidsafe::dht::Contact const &contact, boost::function<bool (JellyInternalClient &)> fct, bool raise = false, bool log = false);

    bool addBigFile(File &file, uint64_t size, std::vector<std::string> const &parts, std::vector<std::string> const &codes);
    bool storeFileData( File &file );
    bool addSmallFile(File &file, const char *filename, uint64_t size);

    void tryFindStorageData();
    
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
