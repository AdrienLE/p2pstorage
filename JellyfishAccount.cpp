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

    scoped_lock l(_challenge_mutex);
    std::ifstream ch(_config_path + "/challenges");
    std::string str;
    if (ch)
    {
        ch.seekg(0, std::ios::end);
        str.resize(ch.tellg());
        ch.seekg(0, std::ios::beg);
        ch.read(&str[0], str.size());
        _challenges = serialize_cast<Challenges>(str);
    }
    _challenges_thread.reset(new boost::thread([this](){this->poseChallenges();}));
}

#define MAX_SECONDS 600

void Jellyfish::poseChallenges()
{
    JellyNodePtr client_node(new JellyNode);
    client_node->Init(static_cast<uint8_t>(_jelly_conf.thread_count),
        mk::KeyPairPtr(), mk::MessageHandlerPtr(), true, _jelly_conf.k,
        _jelly_conf.alpha, _jelly_conf.beta, _jelly_conf.mean_refresh_interval);
    client_node->Start(_jelly_conf.bootstrap_contacts, _jelly_conf.ports);

    while (true)
    {
        maidsafe::Sleep(boost::posix_time::seconds(rand() % MAX_SECONDS));
        scoped_lock l(_challenge_mutex);
        if (_challenges._challenges.size() == 0)
            continue;
        ULOG(INFO) << "Challenges: " << _challenges._challenges.size();
        unsigned i = rand() % _challenges._challenges.size();
        std::vector<mk::Contact> returns;
        Synchronizer<std::vector<mk::Contact> > sync(returns);
        mk::Key k(_challenges._challenges[i].node_id);
        client_node->node()->FindNodes(k, sync, 10);
        ULOG(INFO) << "Challenge to node: " << maidsafe::EncodeToBase64(k.String());
        sync.wait();
        ULOG(INFO) << "Challenge node result: " << sync.result();
        if (sync.result() != mk::kSuccess)
            continue;
        mk::Contact const *good_node = 0;
        for (mk::Contact const &node: returns)
            if (node.node_id().String() == _challenges._challenges[i].node_id)
                good_node = &node;
        ULOG(INFO) << (good_node ? "Found good node" : "Not found node");
        if (!good_node)
            setNodeBad(_challenges._challenges[i], bCantConnect);
        else if (!contactServer(*good_node, [&](JellyInternalClient &client)
        {
            HashStatus status;
            ClientProof proof;
            proof.user = _login;
            client.hashPart(status, _challenges._challenges[i].hash_id, _challenges._challenges[i].salt, proof);
            if (status.status != JellyInternalStatus::SUCCES || status.hash != _challenges._challenges[i].challenge_hash)
                setNodeBad(_challenges._challenges[i], bMissingPart);
            return true;
        }))
            setNodeBad(_challenges._challenges[i], bCantConnect);
        _challenges._challenges.erase(_challenges._challenges.begin() + i);

        std::ofstream challenges_file(_config_path + "/challenges");
        std::string serialized_challenges = serialize_cast<std::string>(_challenges);
        challenges_file.write(&serialized_challenges[0], serialized_challenges.size());
    }
}

void Jellyfish::setNodeBad(Challenge const &ch, KarmaReason r)
{
    Karma karma;
    karma.hour = hoursSinceEpoch();
    karma.node_creation_hour = hoursSinceEpoch();
    karma.randstr = SRandString(16);
    karma.reason = r;
    int result;
    Synchronizer<int> sync(result);
    mk::Key key = getKey(tKarma, ch.node_id);
    std::string value = serialize_cast<std::string>(karma);
    boost::posix_time::time_duration t = boost::posix_time::hours(N_DAYS * 24);
    _jelly_node->node()->Store(key, value, "", t, _private_key_ptr, sync);
    sync.wait();
    ULOG(INFO) << "Found bad node: " << maidsafe::EncodeToBase64(ch.node_id) << " for part " << maidsafe::EncodeToBase64(ch.hash_id) << " (" << KarmaReason2String(r) << ")";
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