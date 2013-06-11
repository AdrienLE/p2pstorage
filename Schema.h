#pragma once

#include "JellyInclude.h"

MAKE_ENUM(Table,
          (tUser)
          (tFile)
          (tStorage)
          (tFileKey)
          (tStoredBlocks)
          (tUserFiles)
          (tFullFile))

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

struct StorageData
{
    StorageData() : size(0) {}
    uint64_t size;
    std::string storage_path; // This info probably shouldn't be stored publicly...

    template<class Archive>
    void serialize(Archive & ar, const unsigned version)
    {
        ar & size;
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

struct File
{
    std::string relative_path;
    std::string salt;
    std::string hash;
    uint64_t size;
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
        ar & real_parts;
        ar & code_parts;
        ar & iv;
        ar & blocks;
        ar & in_dht;
    }
};
