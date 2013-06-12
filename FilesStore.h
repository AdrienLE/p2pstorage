#pragma once

#include "JellyInclude.h"

#include "Schema.h"
#include "JellyfishInternal.h"

class FilesStore
{
public:
    FilesStore(StorageData const &storage_data) : _storage_data(storage_data), _remaining_size(storage_data.size) {}
    JellyInternalStatus::type prepareAdd( std::string const & id, long long size, ClientProof const & client ) ;
    JellyInternalStatus::type add( std::string const & salt, std::string const & id, std::string const & file, ClientProof const & client ) ;
    JellyInternalStatus::type remove( std::string const & id, ClientProof const & client ) ;
    void hashPart( HashStatus & res, std::string const & id, std::string const & salt, ClientProof const & client );
    void localGetFile(FileStatus &_return, const std::string &id, const ClientProof &client);
    void updatePromises();
private:
    struct PromisedBlock
    {
        uint64_t size;
        boost::posix_time::ptime promised_time;
        std::string id;
        ClientProof client;
    };

    boost::recursive_mutex _mutex;
    typedef boost::recursive_mutex::scoped_lock scoped_lock;

    StorageData _storage_data;
    uint64_t _remaining_size;
    std::list<PromisedBlock> _promised;
    boost::unordered_map<std::string, std::list<PromisedBlock>::iterator> _promised_locations;
    boost::unordered_map<std::string, StoredBlock> _stored_blocks;
};
