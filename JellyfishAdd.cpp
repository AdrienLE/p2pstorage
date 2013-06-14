#include "JellyInclude.h"

#include "JellyfishInternal.h"

#include "Jellyfish.h"

#ifdef __APPLE__
#define aligned_alloc(a, b) malloc(b)
#endif

namespace mt = maidsafe::transport;
namespace asymm = maidsafe::rsa;
namespace crypto = maidsafe::crypto;

JellyfishReturnCode Jellyfish::addFile( std::string const &path, std::string const &unique_name )
{
    ULOG(INFO) << "Reading file and getting hash.";
    std::string salt = SRandString(SALT_BYTES);
    std::string hash;
    uint64_t size;
    std::ifstream in(path);
    if (in)
    {
        in.seekg(0, std::ios::end);
        size = in.tellg();
        in.clear();
        in.seekg(0, std::ios::beg);
        hash = HashSalt<crypto::SHA256>(salt, in);
        ULOG(INFO) << "Hash: " << maidsafe::EncodeToBase64(hash);
        in.clear();
        in.seekg(0, std::ios::beg);
    }
    else
    {
        ULOG(WARNING) << "File not found\n";
        return jFileNotFound;
    }
    ULOG(INFO) << "Encoding file.";
    std::vector<std::string> to_remove;
    auto newTemporaryStream = [&]()
    {
        std::string filename = std::string("/tmp/filepart_") + maidsafe::EncodeToBase32(SRandString(16));
        to_remove.push_back(filename);
        return new std::fstream(filename.c_str(), std::fstream::in | std::fstream::out | std::fstream::trunc | std::fstream::binary);
    };
    std::vector<std::ostream *> parts;
    std::generate_n(std::back_inserter(parts), N_PARTS, newTemporaryStream);
    std::vector<std::ostream *> codes;
    std::generate_n(std::back_inserter(codes), N_CODES, newTemporaryStream);

    File file;
    file.real_parts = 1;
    file.code_parts = 0;
    file.hash = hash;
    file.salt = salt;
    file.size = size;
    file.iv = SRandString(crypto::AES256_IVSize);
    file.relative_path = unique_name; // TODO: make it a relative path...

    uint64_t stored_size = encodeFile(file.iv, _user_data.aes256_key, path.c_str(), parts, codes,
        [&](uint64_t sz)
    {
        file.encoded_size = sz;
        std::vector<std::string> p;
        std::vector<std::string> c;
        for (unsigned i = 0; i < parts.size(); ++i)
            p.push_back(to_remove[i]);
        for (unsigned i = 0; i < codes.size(); ++i)
            c.push_back(to_remove[parts.size() + i]);
        return addBigFile(file, sz, p, c);
    },
        [&](const char *filename, uint64_t sz){file.encoded_size = sz; return addSmallFile(file, filename, sz);});
    for (std::string const &fname: to_remove)
        unlink(fname.c_str());
    if (stored_size == (uint64_t)-1)
        return jAddError; // TODO: find a way to return a more precise error
    return jSuccess;
}

// TODO: do a proper two phase commit. Lock unique name
bool Jellyfish::addBigFile(File &file, uint64_t size, std::vector<std::string> const &parts, std::vector<std::string> const &codes)
{
    scoped_lock l(_challenge_mutex);
    ULOG(INFO) << "Adding file bigger than " << THRESHOLD/1000 << "KB";
    ULOG(INFO) << "Searching node.";
    std::vector<std::string> data;
    for (std::string const &p: parts)
        data.push_back(p);
    for (std::string const &p: codes)
        data.push_back(p);

    ClientProof proof;
    proof.user = _login;

    uint64_t max_part_size = 0;

    std::unordered_map<std::string, int> already_stored_on;

    for (std::string const &filename: data)
    {
        std::ifstream block(filename.c_str());
        block.seekg(0, std::ios::end);
        uint64_t size_part = block.tellg();
        max_part_size = std::max(size_part, max_part_size);
        printf("total_size %lu\n", size_part);
        block.clear();
        block.seekg(0, std::ios::beg);
        std::string hash = HashSalt<crypto::SHA256>(file.salt, block);
        block.clear();
        block.seekg(0, std::ios::beg);
        std::string content;
        content.resize(size_part);
        block.read(&content[0], size_part);

        mk::Key key = getKey(tFileKey, SRandString(16));
        std::vector<mk::Contact> contacts;
        Synchronizer<std::vector<mk::Contact> > sync(contacts);
        _jelly_node->node()->FindNodes(key, sync, 100);
        sync.wait();
        if (sync.result() != mk::kSuccess && !contacts.size())
        {
            ULOG(WARNING) << "Could not find node.";
            return false;
        }
        std::sort(contacts.begin(), contacts.end(), [&](mk::Contact const &a, mk::Contact const &b)
        {
            return already_stored_on[a.node_id().String()] < already_stored_on[b.node_id().String()];
        });

        mk::Contact const *stored_on = 0;
        for (mk::Contact const &contact: contacts)
        {
            if (stored_on)
                break;
            ULOG(INFO) << "Trying: " << contact.node_id().ToStringEncoded(mk::NodeId::kBase64);
            if (contact.node_id() == _jelly_node->node()->contact().node_id())
                continue;
            if (contactServer(contact, [&](JellyInternalClient &client)
            {
                ULOG(INFO) << "Found node";
                JellyInternalStatus::type ret = client.prepareAddPart(hash, size_part, proof, file.size);
                if (ret != JellyInternalStatus::SUCCES)
                {
                    ULOG(INFO) << "Error prepareAdd: " << ret;
                    return false;
                }
                ret = client.addPart(file.salt, hash, content, proof, file.size);
                if (ret != JellyInternalStatus::SUCCES)
                    return false;

                FileBlockInfo info;
                info.hash_id = hash;
                info.node_id = contact.node_id().String();
                file.blocks.push_back(info);

                //StoredBlock stored_block;
                //stored_block.salt = file.salt;
                //stored_block.hash_id = hash;
                //stored_block.size = size_part;

                //int store_result;
                //Synchronizer<int> sync_result(store_result);
                //mk::Key k = getKey(tStoredBlocks, contact.node_id().String());
                //std::string value = serialize_cast<std::string>(stored_block);
                //_jelly_node->node()->Store(k, value, "", boost::posix_time::pos_infin, _private_key_ptr, sync_result);
                //sync_result.wait();
                //if (store_result != mk::kSuccess)
                //{
                //    client.removePart(hash, proof);
                //    return false;
                //}
                ULOG(INFO) << "Found good node!";
                for (int i = 0; i < 4; ++i)
                {
                    block.clear();
                    block.seekg(0, std::ios::beg);
                    Challenge challenge;
                    challenge.salt = SRandString(SALT_BYTES);
                    challenge.hash_id = hash;
                    challenge.challenge_hash = HashSalt<crypto::SHA256>(challenge.salt, block);
                    challenge.node_id = contact.node_id().String();
                    block.clear();
                    block.seekg(0, std::ios::beg);
                    _challenges._challenges.push_back(challenge);
                }
                already_stored_on[contact.node_id().String()]++;
                return true;
            }))
                stored_on = &contact;
        }
        if (!stored_on)
        {
            ULOG(WARNING) << "Didn't find node to store file.\n";
            // TODO: remove previous parts!!!
            return false;
        }
    }

    {
        std::ofstream challenges_file(_config_path + "/challenges");
        std::string serialized_challenges = serialize_cast<std::string>(_challenges);
        challenges_file.write(&serialized_challenges[0], serialized_challenges.size());
    }

    return storeFileData(file, max_part_size);
}

bool Jellyfish::addSmallFile(File &file, const char *filename, uint64_t size)
{
    ULOG(INFO) << "Adding file smaller than " << THRESHOLD/1000 << "KB";
    file.in_dht = true;
    std::string to_store;
    to_store.resize(size);
    std::ifstream f(filename);
    f.read(&to_store[0], size);
    int result;
    Synchronizer<int> sync(result);
    mk::Key k = getKey(tFullFile, file.hash);
    _jelly_node->node()->Store(k, to_store, "", boost::posix_time::pos_infin, _private_key_ptr, sync);
    sync.wait();
    if (result != mk::kSuccess)
    {
        ULOG(WARNING) << "Connection error!";
        return false;
    }
    return storeFileData(file);
}

