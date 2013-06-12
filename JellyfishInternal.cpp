#include "JellyInclude.h"

#include "JellyfishInternal.h"

JellyInternalStatus::type JellyfishInternal::prepareAddPart( std::string const & id, int64_t size, ClientProof const & client, int64_t total_size )
{
    return _jelly.localPrepareAdd(id, size, client, total_size);
}

JellyInternalStatus::type JellyfishInternal::addPart( std::string const &salt, std::string const & id, std::string const & file, ClientProof const & client, int64_t total_size )
{
    return _jelly.localAdd(salt, id, file, client, total_size);
}

JellyInternalStatus::type JellyfishInternal::removePart( std::string const & id, ClientProof const & client )
{
    return _jelly.localRemove(id, client);
}

void JellyfishInternal::hashPart( HashStatus &st, std::string const & id, std::string const & salt, ClientProof const & client )
{
    _jelly.hashPart(st, id, salt, client);
}

void JellyfishInternal::getFile( FileStatus& _return, const std::string& id, const ClientProof& client )
{
    _jelly.localGetFile(_return, id, client);
}

