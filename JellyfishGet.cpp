#include "JellyInclude.h"

#include "JellyfishInternal.h"

#include "Jellyfish.h"

#ifdef __APPLE__
#define aligned_alloc(a, b) malloc(b)
#endif

namespace mt = maidsafe::transport;
namespace asymm = maidsafe::rsa;
namespace crypto = maidsafe::crypto;

JellyfishReturnCode Jellyfish::getFile( std::string const &unique_name, std::string const &path )
{
    boost::unordered_set<AbbreviatedFile> files;
    JellyfishReturnCode ret = listFiles(files);
    if (ret != jSuccess)
        return ret;
    AbbreviatedFile abv;
    abv.relative_path = unique_name;
    auto it = files.find(abv);
    if (it == files.end())
        return jFileNotFound;
    mk::FindValueReturns returns;
    {
        Synchronizer<mk::FindValueReturns> sync(returns);
        mk::Key k = getKey(tFile, it->hash);
        _jelly_node->node()->FindValue(k, _private_key_ptr, sync);
        sync.wait();
        if (returns.return_code != mk::kSuccess || returns.values_and_signatures.size() != 1)
        {
            return jFileNotFound;
        }
    }
    File file = serialize_cast<File>(returns.values_and_signatures[0].first);
    if (file.in_dht)
    {
        ULOG(INFO) << "File in DHT";
        mk::FindValueReturns returns;
        Synchronizer<mk::FindValueReturns> sync(returns);
        mk::Key k = getKey(tFullFile, file.hash);
        _jelly_node->node()->FindValue(k, _private_key_ptr, sync);
        sync.wait();
        if (returns.return_code != mk::kSuccess || returns.values_and_signatures.size() != 1)
            return jFileNotFound;
        std::string filename = std::string("/tmp/tmpblock_") + maidsafe::EncodeToBase32(maidsafe::RandomString(16));
        std::ofstream f(filename);
        f.write(&returns.values_and_signatures[0].first[0], returns.values_and_signatures[0].first.size());
        f.close();
        bool ok = decryptFile(file.iv, _user_data.aes256_key, filename, path);
        unlink(filename.c_str());
        return ok ? jSuccess : jUnknownError;
    }
    std::vector<FileBlockInfo> found_blocks;
    std::vector<std::string> filenames;
    std::vector<int> positions;
    int current = -1;
    for (FileBlockInfo const &block: file.blocks)
    {
        if (filenames.size() >= N_PARTS)
            break;
        current++;
        std::string node = block.node_id;
        std::vector<mk::Contact> contacts;
        Synchronizer<std::vector<mk::Contact> > sync_contacts(contacts);
        _jelly_node->node()->FindNodes(mk::Key(node), sync_contacts);
        sync_contacts.wait();
        if (sync_contacts.result() != mk::kSuccess)
        {
            ULOG(INFO) << "Could not find node: " << sync_contacts.result();
            continue;
        }
        mk::Contact const *good_contact = 0;
        for (mk::Contact const &contact: contacts)
        {
            if (contact.node_id().String() == node)
            {
                good_contact = &contact;
                break;
            }
        }
        if (!good_contact)
        {
            ULOG(INFO) << "Could not find good contact.";
            continue;
        }
        bool worked = contactServer(*good_contact, [&](JellyInternalClient &client)
        {
            ClientProof proof;
            proof.user = _login;
            FileStatus status;
            client.getFile(status, block.hash_id, proof);
            if (status.status != JellyInternalStatus::SUCCES)
            {
                ULOG(WARNING) << "Error when getting part " << maidsafe::EncodeToBase64(block.hash_id) << " (" << status.status << ")";
                return false;
            }
            std::istringstream is(status.content);
            std::string hash = HashSalt<crypto::SHA256>(file.salt, is);
            if (hash != block.hash_id)
            {
                ULOG(WARNING) << "Bad hash for block: " << maidsafe::EncodeToBase64(block.hash_id);
                return false;
            }
            std::string filename = std::string("/tmp/tmpblock_") + maidsafe::EncodeToBase32(maidsafe::RandomString(16));
            std::ofstream f(filename);
            f.write(&status.content[0], status.content.size());
            filenames.push_back(filename);
            found_blocks.push_back(block);
            positions.push_back(current);
            ULOG(INFO) << "Here";
            return true;
        }, false, true); // TODO: Should we use worked?
    }
    std::vector<std::istream *> streams;
    for (std::string const &filename: filenames)
        streams.push_back(new std::ifstream(filename));
    bool hasDecoded = decodeFile(file.iv, _user_data.aes256_key, streams, positions, file.encoded_size, path);
    for (std::istream *s: streams)
        delete s;
    for (std::string const &filename: filenames)
        unlink(filename.c_str());
    if (!hasDecoded)
        return jUnknownError;
    return jSuccess;
}
