#include "Jellyfish.h"
#include "maidsafe/common/rsa.h"
#include "maidsafe/common/utils.h"
#include "maidsafe/common/log.h"

#include <boost/lexical_cast.hpp>
#include <boost/format.hpp>
#include <unistd.h>
#include <pwd.h>
#include <exception>

#include "JellyfishInternal.h"
#include "gen-cpp/JellyInternal.h"
#include "thrift/transport/TServerSocket.h"
#include "thrift/transport/TSocket.h"
#include "thrift/protocol/TBinaryProtocol.h"
#include "thrift/transport/TBufferTransports.h"
#include "thrift/concurrency/PosixThreadFactory.h"

namespace mt = maidsafe::transport;
namespace asymm = maidsafe::rsa;
namespace crypto = maidsafe::crypto;

void Jellyfish::runInitNode(boost::filesystem::path const &filepath)
{
    JellyNodePtr client_node(new JellyNode);
    ULOG(INFO) << "Connecting node.\n";
    client_node->Init(static_cast<uint8_t>(_jelly_conf.thread_count),
        mk::KeyPairPtr(), mk::MessageHandlerPtr(), false, _jelly_conf.k,
        _jelly_conf.alpha, _jelly_conf.beta, _jelly_conf.mean_refresh_interval);
    client_node->Start(_jelly_conf.bootstrap_contacts, _jelly_conf.ports);
    std::vector<maidsafe::dht::Contact> contacts;
    client_node->node()->GetBootstrapContacts(&contacts);
    ULOG(INFO) << "Writing contacts file.\n";
    for (maidsafe::dht::Contact const &contact: contacts)
    {
        ULOG(INFO) << contact.node_id().ToStringEncoded(maidsafe::dht::NodeId::kBase64) << "\n";
    }
    WriteContactsToFile(filepath, &contacts);
    ULOG(INFO) << "Contacts file written.\n";
    while (true)
    {
        boost::this_thread::sleep(boost::posix_time::seconds(1));
    }
}

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
    user_data.salt = maidsafe::RandomString(16);
    std::string crypt_key_iv;
    crypto::SecurePassword(password, user_data.salt, user_data.pin, &crypt_key_iv);
    std::string iv = crypt_key_iv.substr(0, crypto::AES256_IVSize);
    std::string crypt_key = crypt_key_iv.substr(crypto::AES256_IVSize, crypto::AES256_KeySize);
    std::string privat, publi;
    asymm::EncodePrivateKey(keys.private_key, &privat);
    user_data.private_key = crypto::SymmEncrypt(privat, crypt_key, iv);
    asymm::EncodePublicKey(keys.public_key, &publi);
    user_data.public_key = publi;
    user_data.aes256_key = maidsafe::RandomString(crypto::AES256_KeySize);
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
    _jelly_node.reset(new JellyNode);
    _jelly_node->Init(static_cast<uint8_t>(_jelly_conf.thread_count),
        _keys, mk::MessageHandlerPtr(), false, _jelly_conf.k,
        _jelly_conf.alpha, _jelly_conf.beta, _jelly_conf.mean_refresh_interval);
    _jelly_node->Start(_jelly_conf.bootstrap_contacts, _jelly_conf.ports);
    _logged_in = true;
    _login = login;
    _user_data = user_data;
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
    
    _jelly_node.reset(new JellyNode);
    _jelly_node->Init(static_cast<uint8_t>(_jelly_conf.thread_count),
                      _keys, mk::MessageHandlerPtr(), false, _jelly_conf.k,
                      _jelly_conf.alpha, _jelly_conf.beta, _jelly_conf.mean_refresh_interval);
    _jelly_node->Start(_jelly_conf.bootstrap_contacts, _jelly_conf.ports);
    _logged_in = true;
    _user_data = user_data;
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

#define UUID_BYTES (128/8)

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
    config_path += "/device_id";
    std::ifstream f(config_path);
    std::string uuid;
    uuid.resize(UUID_BYTES);
    f.read(&uuid[0], UUID_BYTES);
    if (f.gcount() == UUID_BYTES)
        return crypto::Hash<crypto::SHA512>(uuid);
    uuid = maidsafe::RandomString(UUID_BYTES);
    std::ofstream o(config_path);
    o.write(&uuid[0], UUID_BYTES);
    return crypto::Hash<crypto::SHA512>(uuid);
}

// void Commands::FindValueCallback(FindValueReturns find_value_returns,
//                                  std::string path) {
//   if (find_value_returns.return_code != transport::kSuccess) {
//     ULOG(ERROR) << "FindValue operation failed with return code: "
//                 << find_value_returns.return_code
//                 << " (" << ReturnCode2String(mk::ReturnCode(find_value_returns.return_code)) << ")";
//   } else {
//     ULOG(INFO)
//         << boost::format("FindValue returned: %1% value(s), %2% closest "
//                          "contact(s).") %
//                          find_value_returns.values_and_signatures.size() %
//                          find_value_returns.closest_nodes.size();
//     if (find_value_returns.cached_copy_holder.node_id().String() !=
//         kZeroId) {
//       ULOG(INFO)
//           << boost::format(
//                  "Node holding a cached copy of the value: [ %1% ]")
//                  % find_value_returns.cached_copy_holder.node_id().
//                  ToStringEncoded(NodeId::kBase64);
//     }
//     if (find_value_returns.needs_cache_copy.node_id().String() !=
//         kZeroId) {
//       ULOG(INFO)
//           << boost::format("Node needing a cache copy of the values: [ %1% ]")
//                 % find_value_returns.needs_cache_copy.node_id().
//                 ToStringEncoded(NodeId::kBase64);
//     }
//     // Writing only 1st value
//     if (!find_value_returns.values_and_signatures.empty()) {
//       if (path.empty()) {
//         std::string value(find_value_returns.values_and_signatures[0].first);
//         ULOG(INFO) << "Value: " << value;
//       } else {
//         WriteFile(path, find_value_returns.values_and_signatures[0].first);
//       }
//     }
//   }
//   demo_node_->asio_service().post(mark_results_arrived_);
// }

mk::Key Jellyfish::getKey(Jellyfish::Table t, std::string const &key)
{
    std::string table_name;
    switch (t)
    {
        case tUser:
            table_name = "user";
            break;
        case tStorage:
            table_name = "storage";
            break;
        case tFile:
            table_name = "file";
            break;
        default:
            throw std::runtime_error("Bad table in DHT: " + boost::lexical_cast<std::string>(t));
    }
    return mk::Key(crypto::Hash<crypto::SHA512>(table_name + std::string(":") + key));
}

JellyfishReturnCode Jellyfish::initStorage( std::string const &path, uint64_t size )
{
    if (!_logged_in)
        return jNotLoggedIn;
    ULOG(INFO) << "Creating storage path.\n";
    if (!boost::filesystem::create_directories(boost::filesystem::path(path)))
        return jFileSystemError;

    ULOG(INFO) << "Storing storage data.\n";
    _storage_data.size = ((uint64_t)1) << size;
    _storage_data.path = path;
    int result;
    Synchronizer<int> sync(result);
    _jelly_node->node()->Store(getKey(tStorage, _keys->identity), serialize_cast<std::string>(_storage_data), "", boost::posix_time::pos_infin, PrivateKeyPtr(new asymm::PrivateKey(_keys->private_key)), sync);
    sync.wait();
    if (result != mt::kSuccess)
    {
        _storage_data.size = 0;
        _storage_data.path = "";
        return jCouldNotStore;
    }
    return jSuccess;
}

JellyInternalStatus::type Jellyfish::localPrepareAdd( std::string const &id, long long size, ClientProof const &client )
{
    ULOG(INFO) << "localPrepareAdd(" << id << ", " << size << ", " << client.user << ")";
    return JellyInternalStatus::SUCCES;
}

JellyInternalStatus::type Jellyfish::localAdd( std::string const & id, std::string const & file, ClientProof const &client )
{
    ULOG(INFO) << "localAdd(" << id << ", " << file << ", " << client.user << ")";
    return JellyInternalStatus::SUCCES;
}

JellyInternalStatus::type Jellyfish::localRemove( std::string const & id, ClientProof const & client )
{
    ULOG(INFO) << "localRemove(" << id << ", " << client.user << ")";
    return JellyInternalStatus::SUCCES;
}

void Jellyfish::hashPart( HashStatus &res, std::string const & id, std::string const & salt, ClientProof const & client )
{
    ULOG(INFO) << "hashPart(" << id << ", " << maidsafe::EncodeToBase64(salt) << ", " << client.user << ")";
    res.status = JellyInternalStatus::SUCCES;
}

JellyfishReturnCode Jellyfish::addFile( std::string const &path )
{
    ULOG(INFO) << "Reading file.\n";
    std::ifstream in(path, std::ios::in | std::ios::binary);
    std::string contents;
    if (in)
    {
        in.seekg(0, std::ios::end);
        contents.resize(in.tellg());
        in.seekg(0, std::ios::beg);
        in.read(&contents[0], contents.size());
        in.close();
    }
    std::string hash = crypto::Hash<crypto::SHA512>(_login + contents);

    ULOG(INFO) << "Searching node.\n";
    mk::Key key = getKey(tFile, hash);
    std::vector<mk::Contact> contacts;
    Synchronizer<std::vector<mk::Contact> > sync(contacts);
    _jelly_node->node()->FindNodes(key, sync, 100);
    sync.wait();
    if (sync.result != mk::kSuccess && !contacts.size())
        return jNoNodes;

    bool success = false;
    for (mk::Contact const &contact: contacts)
    {
        try
        {
            ULOG(INFO) << contact.node_id().ToStringEncoded(mk::NodeId::kBase64);
            if (contact.node_id() == _jelly_node->node()->contact().node_id())
                continue;
	        boost::shared_ptr<apache::thrift::transport::TSocket> socket(new apache::thrift::transport::TSocket(contact.endpoint().ip.to_string(), contact.endpoint().port + 1));
	        boost::shared_ptr<apache::thrift::transport::TBufferedTransport> transport(new apache::thrift::transport::TBufferedTransport(socket));
	        boost::shared_ptr<apache::thrift::protocol::TBinaryProtocol> protocol(new apache::thrift::protocol::TBinaryProtocol(transport));
            transport->open();
	        JellyInternalClient client(protocol);
	        ClientProof proof;
	        proof.user = _login;
	        JellyInternalStatus::type ret = client.prepareAddPart(key.ToStringEncoded(mk::Key::kBase64), contents.size(), proof);
	        if (ret != JellyInternalStatus::SUCCES)
	            continue;
	        ret = client.addPart(key.ToStringEncoded(mk::Key::kBase64), contents, proof);
	        if (ret != JellyInternalStatus::SUCCES)
	            continue;
	        success = true;
        }
        catch (...)
        {}
    }
    if (!success)
        return jAddError;
    return jSuccess;
}

void PrintNodeInfo(const mk::Contact &contact) {
    ULOG(INFO)
    << boost::format("Node ID:   %1%")
    % contact.node_id().ToStringEncoded(mk::NodeId::kBase64);
    ULOG(INFO)
    << boost::format("Node IP:   %1%") % contact.endpoint().ip.to_string();
    ULOG(INFO)
    << boost::format("Node port: %1%") % contact.endpoint().port;
    ULOG(INFO)
    << boost::format("Debug ID:  %1%") % DebugId(contact);
}


// void Commands::Store(const Arguments &args, bool read_from_file) {
//   std::string value;
//   if (read_from_file) {
//     if (args.size() != 3U) {
//       ULOG(ERROR) << "Invalid number of arguments for storefile command.";
//       return demo_node_->asio_service().post(mark_results_arrived_);
//     }
//     if (!ReadFile(args[1], &value) || value.empty()) {
//       ULOG(ERROR) << "File read error for storefile command.";
//       return demo_node_->asio_service().post(mark_results_arrived_);
//     }
//   } else {
//     value = args[1];
//   }

//   int32_t minutes_to_live(0);
//   try {
//     minutes_to_live = boost::lexical_cast<int32_t>(args[2]);
//   }
//   catch(const std::exception &e) {
//     ULOG(ERROR) << "Invalid ttl for storefile command." << e.what();
//     return demo_node_->asio_service().post(mark_results_arrived_);
//   }

//   bptime::time_duration ttl;
//   if (minutes_to_live == -1)
//     ttl = bptime::pos_infin;
//   else
//     ttl = bptime::minutes(minutes_to_live);

//   Key key(args[0], NodeId::kBase64);
//   if (!key.IsValid())
//     key = Key(crypto::Hash<crypto::SHA512>(args[0]));

//   demo_node_->node()->Store(key, value, "", ttl, null_priv_key_,
//       std::bind(&Commands::StoreCallback, this, args::_1, key, ttl));
// }

// void Commands::StoreCallback(const int &result,
//                              const NodeId &key,
//                              const bptime::time_duration &ttl) {
//   if (result != transport::kSuccess) {
//     ULOG(ERROR) << "Store operation failed with return code: " << result
//                 << " (" << ReturnCode2String(mk::ReturnCode(result)) << ")";
//   } else {
//     ULOG(INFO) <<
//         boost::format("Successfully stored key [ %1% ] with ttl [%2%] min.")
//                       % key.ToStringEncoded(NodeId::kBase64) % ttl.minutes();
//   }
//   demo_node_->asio_service().post(mark_results_arrived_);
// }

// void Commands::FindValue(const Arguments &args, bool write_to_file) {
//   std::string path;
//   if (write_to_file) {
//     if (args.size() != 2U) {
//       ULOG(ERROR) << "Invalid number of arguments for findfile command.";
//       return demo_node_->asio_service().post(mark_results_arrived_);
//     }
//     path = args[1];
//   } else {
//     if (args.size() != 1U) {
//       ULOG(ERROR) << "Invalid number of arguments for findvalue command.";
//       return demo_node_->asio_service().post(mark_results_arrived_);
//     }
//   }

//   Key key(std::string(args.at(0)), NodeId::kBase64);
//   if (!key.IsValid())
//     key = Key(crypto::Hash<crypto::SHA512>(args[0]));

//   demo_node_->node()->FindValue(key, null_priv_key_,
//       std::bind(&Commands::FindValueCallback, this, args::_1, path));
// }

// void Commands::FindValueCallback(FindValueReturns find_value_returns,
//                                  std::string path) {
//   if (find_value_returns.return_code != transport::kSuccess) {
//     ULOG(ERROR) << "FindValue operation failed with return code: "
//                 << find_value_returns.return_code
//                 << " (" << ReturnCode2String(mk::ReturnCode(find_value_returns.return_code)) << ")";
//   } else {
//     ULOG(INFO)
//         << boost::format("FindValue returned: %1% value(s), %2% closest "
//                          "contact(s).") %
//                          find_value_returns.values_and_signatures.size() %
//                          find_value_returns.closest_nodes.size();
//     if (find_value_returns.cached_copy_holder.node_id().String() !=
//         kZeroId) {
//       ULOG(INFO)
//           << boost::format(
//                  "Node holding a cached copy of the value: [ %1% ]")
//                  % find_value_returns.cached_copy_holder.node_id().
//                  ToStringEncoded(NodeId::kBase64);
//     }
//     if (find_value_returns.needs_cache_copy.node_id().String() !=
//         kZeroId) {
//       ULOG(INFO)
//           << boost::format("Node needing a cache copy of the values: [ %1% ]")
//                 % find_value_returns.needs_cache_copy.node_id().
//                 ToStringEncoded(NodeId::kBase64);
//     }
//     // Writing only 1st value
//     if (!find_value_returns.values_and_signatures.empty()) {
//       if (path.empty()) {
//         std::string value(find_value_returns.values_and_signatures[0].first);
//         ULOG(INFO) << "Value: " << value;
//       } else {
//         WriteFile(path, find_value_returns.values_and_signatures[0].first);
//       }
//     }
//   }
//   demo_node_->asio_service().post(mark_results_arrived_);
// }

// void Commands::GetContact(const Arguments &args) {
//   if (args.size() != 1U) {
//     ULOG(ERROR) << "Invalid number of arguments for getcontact command.";
//     return demo_node_->asio_service().post(mark_results_arrived_);
//   }

//   NodeId node_id(args[0], NodeId::kBase64);
//   if (!node_id.IsValid()) {
//     ULOG(ERROR) << "Invalid Node ID for getcontact command.";
//     return demo_node_->asio_service().post(mark_results_arrived_);
//   }

//   demo_node_->node()->GetContact(node_id,
//       std::bind(&Commands::GetContactsCallback, this, args::_1, args::_2));
// }

// void Commands::GetContactsCallback(const int &result, Contact contact) {
//   if (result != transport::kSuccess) {
//     ULOG(ERROR) << "GetContacts operation failed with error code: " << result
//                 << " (" << ReturnCode2String(mk::ReturnCode(result)) << ")";
//   } else {
//     ULOG(INFO) << "GetContacts operation successfully returned:";
//     PrintNodeInfo(contact);
//   }
//   demo_node_->asio_service().post(mark_results_arrived_);
// }

// void Commands::FindNodes(const Arguments &args, bool write_to_file) {
//   std::string path;
//   if (write_to_file) {
//     if (args.size() != 2U) {
//       ULOG(ERROR) << "Invalid number of arguments for findnodesfile command.";
//       return demo_node_->asio_service().post(mark_results_arrived_);
//     }
//     path = args[1];
//   } else {
//     if (args.size() != 1U) {
//       ULOG(ERROR) << "Invalid number of arguments for findnodes command.";
//       return demo_node_->asio_service().post(mark_results_arrived_);
//     }
//   }

//   NodeId node_id(args[0], NodeId::kBase64);
//   if (!node_id.IsValid()) {
//     ULOG(ERROR) << "Invalid Node ID.";
//     return demo_node_->asio_service().post(mark_results_arrived_);
//   }

//   demo_node_->node()->FindNodes(node_id,
//       std::bind(&Commands::FindNodesCallback, this, args::_1, args::_2, path));
// }

// void Commands::FindNodesCallback(const int &result,
//                                  std::vector<Contact> contacts,
//                                  std::string path) {
//   if (result != transport::kSuccess) {
//     ULOG(ERROR) << "FindNodes operation failed with error code: " << result
//                 << " (" << ReturnCode2String(mk::ReturnCode(result)) << ")";
//   } else {
//     if (path.empty()) {
//       ULOG(INFO) << "FindNodes returned the following " << contacts.size()
//                 << " contact(s):";
//       for (auto it = contacts.begin(); it != contacts.end(); ++it)
//         ULOG(INFO) << (*it).node_id().ToStringEncoded(NodeId::kBase64);
//     } else {
//       std::string content;
//       for (auto it = contacts.begin(); it != contacts.end(); ++it)
//         content += ((*it).node_id().ToStringEncoded(NodeId::kBase64) + "\n");
//       WriteFile(path, content);
//     }
//   }
//   demo_node_->asio_service().post(mark_results_arrived_);
// }