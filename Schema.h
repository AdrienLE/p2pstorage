#pragma once

#include "JellyInclude.h"

#include "jellutils/enum.h"

MAKE_ENUM(Table,
          (tUser)
          (tFile)
          (tStorage)
          (tFileKey)
          (tStoredBlocks)
          (tUserFiles)
          (tFullFile)
          (tKarma))

struct UserData
{
    std::string salt;
    uint32_t pin;
    std::string public_key;
    std::string private_key;
    std::string aes256_key;

    template<class Archive>
    void serialize(Archive & ar, const unsigned int version)
    {
        ar & salt;
        ar & pin;
        ar & public_key;
        ar & private_key;
        ar & aes256_key;
    }
};

static uint64_t hoursSinceEpoch()
{
    boost::posix_time::ptime current = boost::posix_time::second_clock::universal_time();
    boost::posix_time::ptime epoch = boost::posix_time::time_from_string("1970-01-01 00:00:00.000");
    boost::posix_time::time_duration span = current - epoch;
    return span.total_seconds() / 3600;
}

struct StorageData
{
    StorageData() : size(0) {}
    uint64_t size;
    uint64_t node_creation_hour;
    std::string storage_path;
    std::string node_id;

    template<class Archive>
    void serialize(Archive & ar, const unsigned version)
    {
        ar & size;
        ar & storage_path;
        ar & node_id;
        ar & node_creation_hour;
    }
};

struct StoredBlock
{
    std::string salt;
    std::string hash_id;
    uint32_t size;

    template<class Archive>
    void serialize(Archive & ar, const unsigned version)
    {
        ar & salt;
        ar & hash_id;
        ar & size;
    }
};

struct Challenge
{
    std::string hash_id;
    std::string salt;
    std::string challenge_hash;
    std::string node_id;

    template<class Archive>
    void serialize(Archive & ar, const unsigned version)
    {
        ar & salt;
        ar & hash_id;
        ar & challenge_hash;
        ar & node_id;
    }
};

struct Challenges
{
    std::vector<Challenge> _challenges;

    template<class Archive>
    void serialize(Archive & ar, const unsigned version)
    {
        ar & _challenges;
    }
};

MAKE_ENUM(KarmaReason,
          (bMissingPart)
          (bCantConnect)
          (bSuspiciousRefuse))

struct Karma
{
    KarmaReason reason;
    uint64_t hour;
    uint64_t node_creation_hour;
    std::string randstr; // Use UUID to make sure that karma can be store even if there is an equivalent one already

    template<class Archive>
    void serialize(Archive & ar, const unsigned version)
    {
        ar & reason;
        ar & hour;
        ar & node_creation_hour;
        ar & randstr;
    }
};

struct FileBlockInfo
{
    std::string hash_id;
    std::string node_id; // Can be compressed by storing the first few bytes.

    template<class Archive>
    void serialize(Archive & ar, const unsigned version)
    {
        ar & hash_id;
        ar & node_id;
    }
};

struct AbbreviatedFile
{
    AbbreviatedFile() : size(0), part_size(0) {}
    std::string hash;
    uint64_t size;
    uint64_t part_size;
    std::string relative_path;

    bool operator<(const AbbreviatedFile &a) const
    {
        return relative_path < a.relative_path;
    }

    bool operator==(const AbbreviatedFile &a) const
    {
        return relative_path == a.relative_path;
    }

    template<class Archive>
    void serialize(Archive & ar, const unsigned version)
    {
        ar & relative_path;
        ar & hash;
        ar & size;
    }
};

static std::size_t hash_value(AbbreviatedFile const& b)
{
    boost::hash<std::string> hasher;
    return hasher(b.relative_path);
}

struct File
{
    std::string relative_path;
    std::string salt;
    std::string hash;
    uint64_t size;
    uint64_t encoded_size;
    uint16_t real_parts;
    uint16_t code_parts;
    std::string iv;
    std::vector<FileBlockInfo> blocks;
    bool in_dht;

    File() : in_dht(false) {}

    template<class Archive>
    void serialize(Archive & ar, const unsigned version)
    {
        ar & relative_path;
        ar & salt;
        ar & hash;
        ar & size;
        ar & encoded_size;
        ar & real_parts;
        ar & code_parts;
        ar & iv;
        ar & blocks;
        ar & in_dht;
    }
};
