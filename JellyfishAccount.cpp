#include "JellyInclude.h"

#include "JellyfishInternal.h"

#include "Jellyfish.h"

#ifdef __APPLE__
#define aligned_alloc(a, b) malloc(b)
#endif

namespace mt = maidsafe::transport;
namespace asymm = maidsafe::rsa;
namespace crypto = maidsafe::crypto;

JellyfishReturnCode Jellyfish::createAccount(std::string const &login, std::string const &password)
{
    JellyNodePtr client_node(new JellyNode);
    ULOG(INFO) << "Connecting node.\n";
    client_node->Init(static_cast<uint8_t>(_jelly_conf.thread_count),
        mk::KeyPairPtr(), mk::MessageHandlerPtr(), true, _jelly_conf.k,
        _jelly_conf.alpha, _jelly_conf.beta, _jelly_conf.mean_refresh_interval);
    client_node->Start(_jelly_conf.bootstrap_contacts, _jelly_conf.ports);

    ULOG(INFO) << "Generating keys.\n";
    asymm::Keys keys;
    asymm::GenerateKeyPair(&keys);
    UserData user_data;
    user_data.pin = rand();
    user_data.salt = SRandString(16);
    std::string crypt_key_iv;
    crypto::SecurePassword(password, user_data.salt, user_data.pin, &crypt_key_iv);
    std::string iv = crypt_key_iv.substr(0, crypto::AES256_IVSize);
    std::string crypt_key = crypt_key_iv.substr(crypto::AES256_IVSize, crypto::AES256_KeySize);
    std::string privat, publi;
    asymm::EncodePrivateKey(keys.private_key, &privat);
    user_data.private_key = crypto::SymmEncrypt(privat, crypt_key, iv);
    asymm::EncodePublicKey(keys.public_key, &publi);
    user_data.public_key = publi;
    std::string aes_key = SRandString(crypto::AES256_KeySize);
    asymm::Encrypt(aes_key, keys.public_key, &user_data.aes256_key);

    std::string value = serialize_cast<std::string>(user_data);
    ULOG(INFO) << "Storing user.\n";
    mk::Key key = getKey(tUser, login);
    int result;
    Synchronizer<int> sync(result);
    client_node->node()->Store(key, value, "", boost::posix_time::pos_infin, PrivateKeyPtr(), sync);
    sync.wait();
    if (result != mt::kSuccess)
        return jCouldNotStore;

    ULOG(INFO) << "Connecting definitely.\n";
    _keys.reset(new asymm::Keys(keys));
    _keys->identity = getNodeIdUser(login);
    _private_key_ptr = mk::PrivateKeyPtr(new asymm::PrivateKey(_keys->private_key));
    _jelly_node.reset(new JellyNode);
    _jelly_node->Init(static_cast<uint8_t>(_jelly_conf.thread_count),
        _keys, mk::MessageHandlerPtr(), false, _jelly_conf.k,
        _jelly_conf.alpha, _jelly_conf.beta, _jelly_conf.mean_refresh_interval);
    _jelly_node->Start(_jelly_conf.bootstrap_contacts, _jelly_conf.ports);
    _logged_in = true;
    _login = login;
    _user_data = user_data;
    _user_data.aes256_key = aes_key;
    startServer();
    return jSuccess;
}

JellyfishReturnCode Jellyfish::login(std::string const &login, std::string const &password)
{
    JellyNodePtr client_node(new JellyNode);
    ULOG(INFO) << "Connecting node.\n";
    client_node->Init(static_cast<uint8_t>(_jelly_conf.thread_count),
                      mk::KeyPairPtr(), mk::MessageHandlerPtr(), true, _jelly_conf.k,
                      _jelly_conf.alpha, _jelly_conf.beta, _jelly_conf.mean_refresh_interval);
    client_node->Start(_jelly_conf.bootstrap_contacts, _jelly_conf.ports);
    
    ULOG(INFO) << "Finding user.\n";
    mk::Key key = getKey(tUser, login);
    mk::FindValueReturns returns;
    Synchronizer<mk::FindValueReturns> sync(returns);
    client_node->node()->FindValue(key, PrivateKeyPtr(), sync);
    sync.wait();
    if (returns.return_code != mt::kSuccess || returns.values_and_signatures.size() != 1)
        return jNoSuchUser;

    ULOG(INFO) << "Checking password.\n";
    UserData user_data = serialize_cast<UserData>(returns.values_and_signatures[0].first);
    std::string crypt_key_iv;
    crypto::SecurePassword(password, user_data.salt, user_data.pin, &crypt_key_iv);
    std::string iv = crypt_key_iv.substr(0, crypto::AES256_IVSize);
    std::string crypt_key = crypt_key_iv.substr(crypto::AES256_IVSize, crypto::AES256_KeySize);
    std::string private_key = crypto::SymmDecrypt(user_data.private_key, crypt_key, iv);
    client_node->Stop(0);
    
    asymm::PrivateKey privat;
    asymm::DecodePrivateKey(private_key, &privat);
    asymm::PublicKey publi(privat);
    std::string str_public;
    asymm::EncodePublicKey(publi, &str_public);
    if (user_data.public_key != str_public)
        return jBadPassword;

    ULOG(INFO) << "Connecting node permanently.\n";
    _login = login;
    _keys.reset(new asymm::Keys);
    _keys->private_key = privat;
    _keys->public_key = publi;
    _keys->identity = getNodeIdUser(login);
    _private_key_ptr = mk::PrivateKeyPtr(new asymm::PrivateKey(privat));
    
    _jelly_node.reset(new JellyNode);
    _jelly_node->Init(static_cast<uint8_t>(_jelly_conf.thread_count),
                      _keys, mk::MessageHandlerPtr(), false, _jelly_conf.k,
                      _jelly_conf.alpha, _jelly_conf.beta, _jelly_conf.mean_refresh_interval);
    _jelly_node->Start(_jelly_conf.bootstrap_contacts, _jelly_conf.ports);
    _logged_in = true;
    std::string aes_copy(user_data.aes256_key);
    asymm::Decrypt(aes_copy, _keys->private_key, &user_data.aes256_key);
    _user_data = user_data;
    tryFindStorageData();
    startServer();
    return jSuccess;
}

void Jellyfish::startServer()
{
    scoped_lock lock(_wait_mutex);
    if (_server)
    {
        _server->stop();
        _server_thread->join();
    }
    mk::FindValueReturns returns;
    Synchronizer<mk::FindValueReturns> sync(returns);
    mk::Key k = getKey(tStorage, _keys->identity);
    _jelly_node->node()->FindValue(k, _private_key_ptr, sync);
    sync.wait();
    if (returns.return_code == mk::kSuccess && returns.values_and_signatures.size() == 1)
    {
        _files_store.reset(new FilesStore(serialize_cast<StorageData>(returns.values_and_signatures[0].first)));
    }
    boost::condition_variable condvar;
    int port = _jelly_node->node()->contact().endpoint().port;
    _server_thread.reset(new boost::thread([&]()
    {
        {
            scoped_lock l(_wait_mutex);

            boost::shared_ptr<apache::thrift::protocol::TBinaryProtocolFactory> protocolFactory(new apache::thrift::protocol::TBinaryProtocolFactory());
            boost::shared_ptr<JellyfishInternal> handler(new JellyfishInternal(*this));
            boost::shared_ptr<JellyInternalProcessor> processor(new JellyInternalProcessor(handler));
            boost::shared_ptr<apache::thrift::transport::TServerSocket> serverTransport(new apache::thrift::transport::TServerSocket(port + 1));
            boost::shared_ptr<apache::thrift::transport::TBufferedTransportFactory> transportFactory(new apache::thrift::transport::TBufferedTransportFactory());

            boost::shared_ptr<apache::thrift::concurrency::ThreadManager> threadManager =  apache::thrift::concurrency::ThreadManager::newSimpleThreadManager(10);
            boost::shared_ptr<apache::thrift::concurrency::PosixThreadFactory> threadFactory(new apache::thrift::concurrency::PosixThreadFactory());
            threadManager->threadFactory(threadFactory);
            threadManager->start();
            _server.reset(new apache::thrift::server::TThreadPoolServer(processor,
                serverTransport,
                transportFactory,
                protocolFactory,
                threadManager));
        }
        condvar.notify_one();
        _server->serve();
    }));
    condvar.wait(lock);
}


std::string Jellyfish::getNodeIdUser(std::string login)
{
    std::string config_path; // This part won't work on Windows...
    const char *home_env = getenv("HOME");
    if (home_env)
        config_path = home_env;
    else
    {
        char buffer[4096];
        struct passwd pw;
        struct passwd *pwp;
        getpwuid_r(getuid(), &pw, buffer, 4096, &pwp);
        if (!pwp)
            throw std::runtime_error("Couldn't find home directory");
        config_path = pw.pw_dir;
    }
    config_path += "/.jellyfish/";
    config_path += login;
    boost::filesystem::create_directories(config_path);
    _config_path = config_path;
    config_path += "/device_id";
    std::ifstream f(config_path);
    std::string uuid;
    uuid.resize(UUID_BYTES);
    f.read(&uuid[0], UUID_BYTES);
    if (f.gcount() == UUID_BYTES)
    {
        return crypto::Hash<crypto::SHA512>(uuid);
    }
    uuid = SRandString(UUID_BYTES);
    std::ofstream o(config_path);
    o.write(&uuid[0], UUID_BYTES);
    return crypto::Hash<crypto::SHA512>(uuid);
}