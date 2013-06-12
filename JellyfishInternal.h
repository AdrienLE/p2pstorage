#pragma once

#include "JellyInclude.h"

#include "gen-cpp/JellyInternal.h"
#include "Jellyfish.h"\

class Jellyfish;

class JellyfishInternal : public JellyInternalIf
{
public:
    JellyfishInternal(Jellyfish &jelly) : _jelly(jelly) {}

    virtual JellyInternalStatus::type prepareAddPart(std::string const & id, int64_t size, ClientProof const & client);
    virtual JellyInternalStatus::type addPart(std::string const &salt, std::string const & id, std::string const & file, ClientProof const & client);
    virtual JellyInternalStatus::type removePart(std::string const & id, ClientProof const & client);
    virtual void hashPart(HashStatus &res, std::string const & id, std::string const & salt, ClientProof const & client);
    virtual void getFile(FileStatus& _return, const std::string& id, const ClientProof& client);

    virtual ~JellyfishInternal() {}

protected:
    Jellyfish &_jelly;
};