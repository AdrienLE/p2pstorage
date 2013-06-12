#pragma once

#include "cryptopp/gzip.h"
#include "cryptopp/hex.h"
#include "cryptopp/aes.h"
#include "cryptopp/modes.h"
#include "cryptopp/osrng.h"
#include "cryptopp/pssr.h"
#include  "cryptopp/ida.h"
#include "cryptopp/pwdbased.h"
#include "cryptopp/cryptlib.h"

#include <boost/shared_array.hpp>

template<class H, class Stream>
std::string HashSalt(std::string const &salt, Stream &stream)
{
    H hash;
    std::string result;
    hash.Update((byte *)&salt[0], salt.size());
    CryptoPP::FileSource(stream, true,
        new CryptoPP::HashFilter(hash, new CryptoPP::StringSink(result)));
    return result;
}

template<class SType>
std::string SRandString(SType size)
{
    static boost::thread_specific_ptr<CryptoPP::AutoSeededRandomPool> prng;
    if (!prng.get())
        prng.reset(new CryptoPP::AutoSeededRandomPool());
    CryptoPP::AutoSeededRandomPool &rng = *prng;
    boost::shared_array<byte> bytes(new byte[size]);
    rng.GenerateBlock(bytes.get(), size);
    std::string s;
    s.resize(size);
    memcpy(&s[0], bytes.get(), size);
    return s;
}