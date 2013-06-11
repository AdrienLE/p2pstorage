#include "JellyInclude.h"

#include "FilesStore.h"


namespace crypto = maidsafe::crypto;

void FilesStore::hashPart( HashStatus & res, std::string const & id, std::string const & salt, ClientProof const & client )
{
    scoped_lock l(_mutex);
    if (_stored_blocks.find(id) == _stored_blocks.end())
    {
        res.status = JellyInternalStatus::INVALID_REQUEST;
        return;
    }
    std::ifstream f((_storage_data.storage_path + "/" + maidsafe::EncodeToBase32(id)).c_str());
    res.hash = HashSalt<crypto::SHA256>(salt, f);
    res.status = JellyInternalStatus::SUCCES;
}

// TODO: actually create the file in advance
JellyInternalStatus::type FilesStore::prepareAdd( std::string const & id, long long size, ClientProof const & client )
{
    scoped_lock l(_mutex);
    updatePromises();
    if (_remaining_size < (uint64_t)size)
        return JellyInternalStatus::NO_SPACE_LEFT;
    if (_promised_locations.find(id) != _promised_locations.end())
        return JellyInternalStatus::INVALID_REQUEST;
    PromisedBlock b;
    b.size = size;
    b.promised_time = boost::posix_time::second_clock::local_time();
    b.client = client;
    b.id = id;
    _promised.push_back(b);
    _remaining_size -= size;
    auto it = _promised.end();
    --it;
    _promised_locations[id] = it;
    return JellyInternalStatus::SUCCES;
}

// TODO: the file writing thing should be slow and therefore should be done outside the mutex
JellyInternalStatus::type FilesStore::add( std::string const & salt, std::string const & id, std::string const & file, ClientProof const & client )
{
    scoped_lock l(_mutex);
    updatePromises();
    if (_promised_locations.find(id) == _promised_locations.end())
        return JellyInternalStatus::INVALID_REQUEST;
    std::list<PromisedBlock>::iterator it = _promised_locations[id];
    if (it->size != file.size() || it->client != client)
        return JellyInternalStatus::INVALID_REQUEST;
    std::istringstream is(file);
    std::string hash = HashSalt<crypto::SHA256>(salt, is);
    if (hash != id)
        return JellyInternalStatus::INVALID_REQUEST;
    std::ofstream f((_storage_data.storage_path + "/" + maidsafe::EncodeToBase32(id)).c_str());
    f.write(&file[0], file.size()); // TODO: test if file is indeed written
    StoredBlock block;
    block.hash_id = id;
    block.salt = salt;
    block.size = it->size;
    _stored_blocks[id] = block;
    _promised.erase(it);
    return JellyInternalStatus::SUCCES;
}

JellyInternalStatus::type FilesStore::remove( std::string const & id, ClientProof const & client )
{
    scoped_lock l(_mutex);
    if (_stored_blocks.find(id) == _stored_blocks.end())
        return JellyInternalStatus::INVALID_REQUEST;
    const StoredBlock &block = _stored_blocks[id];
    _remaining_size += block.size;
    _stored_blocks.erase(id);
    unlink((_storage_data.storage_path + "/" + maidsafe::EncodeToBase32(id)).c_str());
    return JellyInternalStatus::SUCCES;
}

void FilesStore::updatePromises()
{
    scoped_lock l(_mutex);
    boost::posix_time::ptime current(boost::posix_time::second_clock::local_time());
    boost::posix_time::ptime ten_mn_ago = current - boost::posix_time::time_duration(boost::posix_time::minutes(10));
    while (!_promised.empty() && _promised.front().promised_time < ten_mn_ago)
    {
        _remaining_size -= _promised.front().size;
        _promised_locations.erase(_promised.front().id);
        _promised.pop_front();
    }
}
