#include "JellyInclude.h"

#include "JellyfishInternal.h"

#include "Jellyfish.h"

#ifdef __APPLE__
#define aligned_alloc(a, b) malloc(b)
#endif

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

JellyfishReturnCode Jellyfish::initStorage( std::string const &path, uint64_t size )
{
    if (!_logged_in)
        return jNotLoggedIn;
    if (_files_store)
        return jAlreadyInitialized; // Can't reinitialize storage for now
    ULOG(INFO) << "Creating storage path.\n";
    if (!boost::filesystem::create_directories(boost::filesystem::path(path)))
        return jFileSystemError;

    ULOG(INFO) << "Storing storage data.\n";
    StorageData storage_data;
    storage_data.size = ((uint64_t)1) << (size + 29);
    storage_data.storage_path = path;
    int result;
    Synchronizer<int> sync(result);
    mk::Key k = getKey(tStorage, _keys->identity);
    _jelly_node->node()->Store(k, serialize_cast<std::string>(storage_data), "", boost::posix_time::pos_infin, _private_key_ptr, sync);
    sync.wait();
    if (result != mt::kSuccess)
    {
        return jCouldNotStore;
    }
    _files_store.reset(new FilesStore(storage_data));
    return jSuccess;
}

void Jellyfish::tryFindStorageData()
{
    std::string path = _config_path + "/storage_data";
    std::ifstream f(path);
    if (!f)
        return;
    f.seekg(0, std::ios::end);
    uint64_t size = f.tellg();
    f.clear();
    f.seekg(0, std::ios::beg);
    std::string content;
    content.resize(size);
    f.read(&content[0], size);
    _files_store.reset(new FilesStore(serialize_cast<StorageData>(content)));
}