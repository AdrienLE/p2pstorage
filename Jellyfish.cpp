#include "Jellyfish.h"

#include "maidsafe/common/rsa.h"
#include "maidsafe/common/utils.h"
#include "maidsafe/common/log.h"

#include "JellyfishInternal.h"
#include "gen-cpp/JellyInternal.h"

#include "thrift/transport/TServerSocket.h"
#include "thrift/transport/TSocket.h"
#include "thrift/protocol/TBinaryProtocol.h"
#include "thrift/transport/TBufferTransports.h"
#include "thrift/concurrency/PosixThreadFactory.h"

extern "C"
{
#include "jerasure/jerasure.h"
#include "jerasure/cauchy.h"
};

#include <boost/lexical_cast.hpp>
#include <boost/format.hpp>
#include <boost/shared_array.hpp>
#include <unistd.h>
#include <pwd.h>
#include <exception>
#include <sstream>
#include <fstream>

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
    std::string aes_key = maidsafe::RandomString(crypto::AES256_KeySize);
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

#define W 15
#define OPTIMAL_PACKET_SIZE 2800

static int getPacketSize(uint64_t size, int n_parts)
{
    int min = OPTIMAL_PACKET_SIZE;
    int minpacketsize = OPTIMAL_PACKET_SIZE;
    for (int packetsize = minpacketsize; packetsize > 100; --packetsize)
    {
        if (size % (n_parts*W*packetsize*sizeof(int)) + minpacketsize - packetsize < min)
        {
            min = size % (n_parts*W*packetsize*sizeof(int));
            minpacketsize = packetsize;
        }
    }
    return minpacketsize;
}

void Jellyfish::getPartsCodes(std::istream &content, uint64_t size, int n_parts, int n_codes, std::vector<std::ostream *> const &parts, std::vector<std::ostream *> const &codes)
{
    int packetsize = getPacketSize(size, n_parts);

    uint64_t real_size = size;
    while (real_size % (n_parts*W*packetsize*8) != 0)
        real_size++;

    boost::shared_ptr<int> matrix(::cauchy_good_general_coding_matrix(n_parts, n_codes, W), free);
    boost::shared_ptr<int> bitmatrix(::jerasure_matrix_to_bitmatrix(n_parts, n_codes, W, matrix.get()), free);
    boost::shared_ptr<int *> schedule(::jerasure_smart_bitmatrix_to_schedule(n_parts, n_codes, W, bitmatrix.get()), ::jerasure_free_schedule);
    std::vector<char *> cparts(n_parts);
    std::vector<char *> ccodes(n_codes);
    char *buffer = (char*)aligned_alloc(sizeof(long), packetsize*8*W*n_parts + sizeof(long));
    for (int i = 0; i < n_parts; ++i)
        cparts[i] = buffer + i * packetsize * 8 * W;
    for (int i = 0; i < n_codes; ++i)
        ccodes[i] = (char*)aligned_alloc(sizeof(long), packetsize*8*W + sizeof(long));
    for (size_t done = 0; done < real_size; done += packetsize * 8 * W * n_parts)
    {
        memset(buffer, 0, n_parts * packetsize * 8 * W);
        content.read(&buffer[0], n_parts * packetsize * 8 * W);
        printf("jerasure_schedule_encode(%d, %d, %d, %p, %p, %p, %d, %d)\n", n_parts, n_codes, W, schedule.get(), &cparts[0], &ccodes[0], packetsize * W * 8, packetsize);
        ::jerasure_schedule_encode(n_parts, n_codes, W, schedule.get(), &cparts[0], &ccodes[0], packetsize * W * 8, packetsize);
        auto cpy = [=](std::vector<char *> const &d, std::vector<std::ostream *> const &to)
        {
            for (size_t i = 0; i < to.size(); ++i)
                to[i]->write(d[i], packetsize * 8 * W);
        };
        cpy(cparts, parts);
        cpy(ccodes, codes);
    }
    auto flush = [](std::vector<std::ostream *> const &v)
    {
        for (std::ostream *o: v)
        {
            o->flush();
        }
    };
    flush(parts);
    flush(codes);
    free(buffer);
    for (char *c: ccodes)
        free(c);
}

bool Jellyfish::getContentFromCodes(std::vector<std::istream *> in, std::vector<int> position, int n_parts, int n_codes, uint64_t size, std::ostream &out)
{
    int packetsize = getPacketSize(size, n_parts);
    uint64_t real_size = size;
    while (real_size % (n_parts*W*packetsize*8) != 0)
        real_size++;

    boost::shared_ptr<int> matrix(::cauchy_good_general_coding_matrix(n_parts, n_codes, W), free);
    boost::shared_ptr<int> bitmatrix(::jerasure_matrix_to_bitmatrix(n_parts, n_codes, W, matrix.get()), free);

    int total_parts = n_codes + n_parts;
    std::vector<int> erasures;
    int last_unknown = 0;
    for (int p: position)
    {
        for (int i = last_unknown; i < p; ++i)
            erasures.push_back(i);
        last_unknown = p + 1;
    }
    for (int i = last_unknown; i < total_parts; ++i)
        erasures.push_back(i);
    erasures.push_back(-1);

    for (int erasure: erasures)
        printf("erasure: %d\n", erasure);

    boost::shared_ptr<char> buffer((char*)aligned_alloc(sizeof(long), packetsize * 8 * W * total_parts + sizeof(long) * total_parts), free);
    std::vector<char *> data(n_parts);
    for (int i = 0; i < n_parts; ++i)
    {
        data[i] = buffer.get() + i * (packetsize * W * 8 + sizeof(long));
    }
    std::vector<char *> codes(n_codes);
    for (int i = 0; i < n_codes; ++i)
    {
        codes[i] = buffer.get() + (n_parts + i) * (packetsize * W * 8 + sizeof(long));
    }
    for (uint64_t total_size = 0; total_size < real_size; total_size += packetsize * W * 8 * n_parts)
    {
        memset(buffer.get(), 0, packetsize * 8 * W * total_parts + sizeof(long) * total_parts);
        for (int i = 0; i < position.size(); ++i)
        {
            int pos = position[i];
            in[i]->read((pos < n_parts) ? data[position[i]] : codes[position[i] - n_parts], packetsize * 8 * W);
        }
        for (int i = 0; i < data.size(); ++i)
        {
            unsigned int checksum = 0;
            for (int j = 0; j < packetsize * 8 * W; ++j)
                checksum += data[i][j];
            printf("checksum: %u\n", checksum);
        }
        for (int i = 0; i < codes.size(); ++i)
        {
            unsigned int checksum = 0;
            for (int j = 0; j < packetsize * 8 * W; ++j)
                checksum += codes[i][j];
            printf("checksum: %u\n", checksum);
        }
        printf("jerasure_schedule_decode_lazy(%d, %d, %d, %p, %p, %p, %p, %d, %d, 1)\n", n_parts, n_codes,
            W, bitmatrix.get(), &erasures[0], &data[0], &codes[0], packetsize * 8 * W, packetsize);
        if (::jerasure_schedule_decode_lazy(n_parts, n_codes, W, bitmatrix.get(),
                                            &erasures[0], &data[0], &codes[0],
                                            packetsize * 8 * W, packetsize, 1) != 0)
        {
            return false;
        }
        printf("c: '%c'\n", data[0][0]);
        for (int i = 0; i < n_parts; ++i)
        {
            out.write(data[i], std::min((uint64_t)packetsize * 8 * W, size - total_size));
            total_size += packetsize * 8 * W;
        }
    }
    return true;
}

void lol()
{
    std::string s = "a";
    for (int i = 0; i < 16; ++i)
        s += s;

    std::ofstream f("a");
    f.write(s.c_str(), s.size());

    printf("packet: %d, buf: %d\n", getPacketSize(s.size(), 5), W*8*getPacketSize(s.size(), 5)*5);

    std::istringstream is(s);
    std::vector<std::ostream *> parts(5), codes(10);
    std::generate(parts.begin(), parts.end(), [](){return new std::ostringstream();});
    std::generate(codes.begin(), codes.end(), [](){return new std::ostringstream();});
    //for (int current = 0; current < 5; ++current)
    //{
    //    parts[current] = new std::ofstream(std::string("k_")+boost::lexical_cast<std::string>(current));
    //}
    //for (int current = 0; current < 10; ++current)
    //{
    //    codes[current] = new std::ofstream(std::string("m_")+boost::lexical_cast<std::string>(current));
    //}
    Jellyfish::getPartsCodes(is, s.size(), 5, 10, parts, codes);
    std::vector<std::ostream *> streams(parts);
    std::copy(codes.begin(), codes.end(), std::back_inserter(streams));
    std::vector<std::istream *> i;
    std::transform(streams.begin(), streams.end(), std::back_inserter(i), [](std::ostream *o)
    {
        return new std::istringstream(((std::ostringstream *)o)->str());
    });
    std::vector<int> positions = {10, 11, 12, 13, 14};
    //for (int i = 0; i < 5; ++i)
    //{
    //    int r;
    //    while (true)
    //    {
    //        r = rand() % 15;
    //        bool cont = false;
    //        for (int p: positions)
    //            if (r == p)
    //                cont = true;
    //        if (!cont)
    //            break;
    //    }
    //    positions.push_back(r);
    //}
    std::sort(positions.begin(), positions.end());
    printf("%d %d %d %d %d\n", positions[0], positions[1], positions[2], positions[3], positions[4]);
    std::vector<std::istream *> iparts;
    std::transform(positions.begin(), positions.end(), std::back_inserter(iparts), [&](int p)
    {
        return i[p];
    });
    std::ostringstream out;
    Jellyfish::getContentFromCodes(iparts, positions, 5, 10, s.size(), out);
    std::string a = out.str();
    //printf("%s\n\n%s\n\n", a.c_str(), s.c_str());
    for (int i = 0; i < s.size(); ++i)
    {
        if (a[i] != s[i]);
        //printf("%d: %c - %c\n", i, a[i], s[i]);
    }
    //printf("%s\n", maidsafe::EncodeToBase64(((std::ostringstream *)streams[disp % 15])->str()).c_str());
}

int main2(int ac, char **av)
{
    int n = 1;
    if (ac == 2)
        n = atoi(av[1]);
    for (int i = 0; i < n; ++i)
        lol();
    return 0;
}

#define SALT_BYTES 16

JellyfishReturnCode Jellyfish::addFile( std::string const &path )
{
    ULOG(INFO) << "Reading file.\n";
    uint64_t size;
    std::ifstream in(path, std::ios::in | std::ios::binary);
    std::string contents;
    if (in)
    {
        in.seekg(0, std::ios::end);
        size = in.tellg();
        contents.resize(size);
        in.seekg(0, std::ios::beg);
        in.read(&contents[0], contents.size());
        in.close();
    }

    std::vector<std::string> parts;
    std::vector<std::string> codes;
    //getPartsCodes(content, &parts, &codes);

    std::string salt = maidsafe::RandomString(SALT_BYTES);
    std::string hash = crypto::Hash<crypto::SHA256>(salt + contents);

    ULOG(INFO) << "Searching node.\n";
    mk::Key key = getKey(tFileKey, hash);
    std::vector<mk::Contact> contacts;
    Synchronizer<std::vector<mk::Contact> > sync(contacts);
    _jelly_node->node()->FindNodes(key, sync, 100);
    sync.wait();
    if (sync.result != mk::kSuccess && !contacts.size())
        return jNoNodes;

    bool success = false;
    mk::Contact const *stored_on;
    std::string iv = maidsafe::RandomString(crypto::AES256_IVSize);
    for (mk::Contact const &contact: contacts)
    {
        if (success)
            break;
        ULOG(INFO) << "Trying: " << contact.node_id().ToStringEncoded(mk::NodeId::kBase64);
        if (contact.node_id() == _jelly_node->node()->contact().node_id())
            continue;
        success = contactServer(contact, [&](JellyInternalClient &client)
        {
            std::string encrypted_contents = crypto::SymmDecrypt(contents, _user_data.aes256_key, iv);
            ClientProof proof;
            proof.user = _login;
            JellyInternalStatus::type ret = client.prepareAddPart(hash, encrypted_contents.size(), proof);
            if (ret != JellyInternalStatus::SUCCES)
                return false;
            ret = client.addPart(hash, encrypted_contents, proof);
            if (ret != JellyInternalStatus::SUCCES)
                return false;
            StoredBlock block;
            block.file_id = hash;
            block.hash_id = hash;
            block.size = size;
            int store_result;
            Synchronizer<int> sync_result(store_result);
            _jelly_node->node()->Store(getKey(tClientParts, hash), serialize_cast<std::string>(block), "", boost::posix_time::pos_infin, _private_key_ptr, sync_result);
            sync_result.wait();
            if (store_result != mk::kSuccess)
            {
                client.removePart(key.ToStringEncoded(mk::Key::kBase64), proof);
                return false;
            }
            stored_on = &contact;
            ULOG(INFO) << "Found good node!";
            return true;
        });
    }
    if (!success)
        return jAddError;
    FileBlockInfo fp;
    fp.node_id = stored_on->node_id().String();
    fp.iv = iv;
    fp.hash_id = hash;

    File file;
    file.real_parts = 1;
    file.code_parts = 0;
    file.hash = hash;
    file.salt = salt;
    file.size = size;
    file.relative_path = path.c_str(); // TODO: make it a relative path...
    file.blocks.push_back(fp);
    int store_result;
    Synchronizer<int> sync_result(store_result);
    _jelly_node->node()->Store(getKey(tFile, hash), serialize_cast<std::string>(file), "", boost::posix_time::pos_infin, _private_key_ptr, sync_result);
    sync_result.wait();
    if (store_result != mk::kSuccess)
        return jDisconnected;
    _jelly_node->node()->Store(getKey(tUserFiles, _login), hash, "", boost::posix_time::pos_infin, _private_key_ptr, sync_result);
    sync_result.wait();
    if (store_result != mk::kSuccess)
        return jDisconnected;
    return jSuccess;
}

bool Jellyfish::contactServer(maidsafe::dht::Contact const &contact, boost::function<bool (JellyInternalClient &)> fct, bool raise, bool log)
{
    static FILE *nullfile;
    if (!nullfile)
        nullfile = fopen("/dev/null", "w");
    FILE *err = stderr;
    try
    {
        stderr = nullfile;
        boost::shared_ptr<apache::thrift::transport::TSocket> socket(new apache::thrift::transport::TSocket(contact.endpoint().ip.to_string(), contact.endpoint().port + 1));
        boost::shared_ptr<apache::thrift::transport::TBufferedTransport> transport(new apache::thrift::transport::TBufferedTransport(socket));
        boost::shared_ptr<apache::thrift::protocol::TBinaryProtocol> protocol(new apache::thrift::protocol::TBinaryProtocol(transport));
        transport->open();
        stderr = err;
        JellyInternalClient client(protocol);
        return fct(client);
    }
    catch (std::exception const &e)
    {
        stderr = err;
        if (log)
            ULOG(WARNING) << "Exeption in connecting server: " << e.what();
        if (raise)
            throw;
        return false;
    }
    catch (...)
    {
        stderr = err;
        if (raise)
            throw;
        return false;
    }
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

mk::Key Jellyfish::getKey(Jellyfish::Table t, std::string const &key)
{
    std::string table_name = Table2String(t);
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
    _storage_path = path;
    int result;
    Synchronizer<int> sync(result);
    _jelly_node->node()->Store(getKey(tStorage, _keys->identity), serialize_cast<std::string>(_storage_data), "", boost::posix_time::pos_infin, _private_key_ptr, sync);
    sync.wait();
    if (result != mt::kSuccess)
    {
        _storage_data.size = 0;
        return jCouldNotStore;
    }
    return jSuccess;
}

JellyInternalStatus::type Jellyfish::localPrepareAdd( std::string const &id, long long size, ClientProof const &client )
{
    ULOG(INFO) << "localPrepareAdd(" << maidsafe::EncodeToHex(id) << ", " << size << ", " << client.user << ")";
    return JellyInternalStatus::SUCCES;
}

JellyInternalStatus::type Jellyfish::localAdd( std::string const & id, std::string const & file, ClientProof const &client )
{
    ULOG(INFO) << "localAdd(" << maidsafe::EncodeToHex(id) << ", " << maidsafe::EncodeToBase64(file) << ", " << client.user << ")";
    return JellyInternalStatus::SUCCES;
}

JellyInternalStatus::type Jellyfish::localRemove( std::string const & id, ClientProof const & client )
{
    ULOG(INFO) << "localRemove(" << maidsafe::EncodeToHex(id) << ", " << client.user << ")";
    return JellyInternalStatus::SUCCES;
}

void Jellyfish::hashPart( HashStatus &res, std::string const & id, std::string const & salt, ClientProof const & client )
{
    ULOG(INFO) << "hashPart(" << maidsafe::EncodeToHex(id) << ", " << maidsafe::EncodeToBase64(salt) << ", " << client.user << ")";
    res.status = JellyInternalStatus::SUCCES;
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