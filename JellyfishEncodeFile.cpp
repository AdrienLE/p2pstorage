#include "JellyInclude.h"

#include "JellyfishInternal.h"

#include "Jellyfish.h"

#ifdef __APPLE__
#define aligned_alloc(a, b) malloc(b)
#endif

namespace mt = maidsafe::transport;
namespace asymm = maidsafe::rsa;
namespace crypto = maidsafe::crypto;

static int getPacketSize(uint64_t size, int n_parts)
{
    unsigned min = OPTIMAL_PACKET_SIZE;
    unsigned minpacketsize = OPTIMAL_PACKET_SIZE;
    for (unsigned packetsize = minpacketsize; packetsize > 8 && packetsize > size / 1000; --packetsize)
    {
        if ((size < n_parts*W*packetsize*8 || size % (n_parts*W*packetsize*8) + minpacketsize - packetsize) < min && packetsize % 8 == 0)
        {
            min = size % (n_parts*W*packetsize*8);
            minpacketsize = packetsize;
        }
    }
    return minpacketsize;
}

void Jellyfish::getPartsCodes(std::istream &content, uint64_t size, int n_parts, int n_codes, std::vector<std::ostream *> const &parts, std::vector<std::ostream *> const &codes)
{
    int packetsize = getPacketSize(size, n_parts);

    uint64_t real_size = size;
    while (real_size % (n_parts*W*packetsize*8) != 0)
        real_size++;

    boost::shared_ptr<int> matrix(::cauchy_good_general_coding_matrix(n_parts, n_codes, W), free);
    boost::shared_ptr<int> bitmatrix(::jerasure_matrix_to_bitmatrix(n_parts, n_codes, W, matrix.get()), free);
    boost::shared_ptr<int *> schedule(::jerasure_smart_bitmatrix_to_schedule(n_parts, n_codes, W, bitmatrix.get()), ::jerasure_free_schedule);
    std::vector<char *> cparts(n_parts);
    std::vector<char *> ccodes(n_codes);
    char *buffer = (char*)aligned_alloc(sizeof(long), packetsize*8*W*n_parts);
    for (int i = 0; i < n_parts; ++i)
        cparts[i] = buffer + i * packetsize * 8 * W;
    for (int i = 0; i < n_codes; ++i)
        ccodes[i] = (char*)aligned_alloc(sizeof(long), packetsize*8*W);
    for (size_t done = 0; done < real_size; done += packetsize * 8 * W * n_parts)
    {
        memset(buffer, 0, n_parts * packetsize * 8 * W);
        content.read(&buffer[0], n_parts * packetsize * 8 * W);
        ::jerasure_schedule_encode(n_parts, n_codes, W, schedule.get(), &cparts[0], &ccodes[0], packetsize * W * 8, packetsize);
        auto cpy = [=](std::vector<char *> const &d, std::vector<std::ostream *> const &to)
        {
            for (size_t i = 0; i < to.size(); ++i)
                to[i]->write(d[i], packetsize * 8 * W);
        };
        cpy(cparts, parts);
        cpy(ccodes, codes);
    }
    auto flush = [](std::vector<std::ostream *> const &v)
    {
        for (std::ostream *o: v)
        {
            o->flush();
        }
    };
    flush(parts);
    flush(codes);
    free(buffer);
    for (char *c: ccodes)
        free(c);
}

bool Jellyfish::getContentFromCodes(std::vector<std::istream *> in, std::vector<int> position, int n_parts, int n_codes, uint64_t size, std::ostream &out)
{
    int packetsize = getPacketSize(size, n_parts);
    uint64_t real_size = size;
    while (real_size % (n_parts*W*packetsize*8) != 0)
        real_size++;

    boost::shared_ptr<int> matrix(::cauchy_good_general_coding_matrix(n_parts, n_codes, W), free);
    boost::shared_ptr<int> bitmatrix(::jerasure_matrix_to_bitmatrix(n_parts, n_codes, W, matrix.get()), free);

    int total_parts = n_codes + n_parts;
    std::vector<int> erasures;
    int last_unknown = 0;
    for (int p: position)
    {
        for (int i = last_unknown; i < p; ++i)
            erasures.push_back(i);
        last_unknown = p + 1;
    }
    for (int i = last_unknown; i < total_parts; ++i)
        erasures.push_back(i);
    erasures.push_back(-1);

    boost::shared_ptr<char> buffer((char*)aligned_alloc(sizeof(long), packetsize * 8 * W * total_parts), free);
    std::vector<char *> data(n_parts);
    for (int i = 0; i < n_parts; ++i)
    {
        data[i] = buffer.get() + i * (packetsize * W * 8);
    }
    std::vector<char *> codes(n_codes);
    for (int i = 0; i < n_codes; ++i)
    {
        codes[i] = buffer.get() + (n_parts + i) * (packetsize * W * 8);
    }
    for (uint64_t total_size = 0; total_size < real_size; )
    {
        memset(buffer.get(), 0, packetsize * 8 * W * total_parts);
        for (unsigned i = 0; i < position.size(); ++i)
        {
            int pos = position[i];
            in[i]->read((pos < n_parts) ? data[position[i]] : codes[position[i] - n_parts], packetsize * 8 * W);
        }
        if (::jerasure_schedule_decode_lazy(n_parts, n_codes, W, bitmatrix.get(),
                                            &erasures[0], &data[0], &codes[0],
                                            packetsize * 8 * W, packetsize, 1) != 0)
        {
            return false;
        }
        for (int i = 0; i < n_parts; ++i)
        {
            if (size > total_size)
                out.write(data[i], std::min((uint64_t)packetsize * 8 * W, size - total_size));
            total_size += packetsize * 8 * W;
        }
    }
    return true;
}

uint64_t Jellyfish::encodeFile(std::string const &iv, std::string const &key, const char *filename_in, std::vector<std::ostream *> const &parts, std::vector<std::ostream *> const &codes, boost::function<bool (uint64_t size)> big_callback, boost::function<bool (const char *, uint64_t)> small_callback)
{
    if (key.size() < crypto::AES256_KeySize || iv.size() < crypto::AES256_IVSize)
    {
        DLOG(WARNING) << "Undersized key or IV";
        return -1;
    }
    bool success_a = true, success_b = true;
    uint64_t size;
    pipe_link(
        [&](const char *filename)
    {
        try
        {
            byte bkey[crypto::AES256_KeySize], biv[crypto::AES256_IVSize];

            CryptoPP::StringSource(key.substr(0, crypto::AES256_KeySize), true,
                new CryptoPP::ArraySink(bkey, sizeof(bkey)));
            CryptoPP::StringSource(iv.substr(0, crypto::AES256_IVSize), true,
                new CryptoPP::ArraySink(biv, sizeof(biv)));

            CryptoPP::CFB_Mode<CryptoPP::AES>::Encryption encryptor(bkey, sizeof(bkey), biv);
            CryptoPP::FileSource(filename_in, true,
                new CryptoPP::Gzip(
                new CryptoPP::StreamTransformationFilter(encryptor,
                new CryptoPP::FileSink(filename)), 1));
        }
        catch (std::exception const &e)
        {
            ULOG(WARNING) << "Exception: " << e.what();
            success_a = false;
        }
        catch (...)
        {
            success_a = false;
        }
    },
        [&](const char *filename)
    {
        printf("there %s\n", filename);
        std::ifstream f(filename);
        if (f)
        {
            f.seekg(0, std::ios::end);
            size = f.tellg();
            f.clear();
            f.seekg(0, std::ios::beg);
        }
        printf("size %lu\n", size);
        if (size > THRESHOLD)
        {
            Jellyfish::getPartsCodes(f, size, N_PARTS, N_CODES, parts, codes);
            f.close();
            success_b = big_callback(size);
        }
        else
        {
            f.close();
            success_b = small_callback(filename, size);
        }
    }, true);
    if (!success_a || !success_b)
        return -1;
    return size;
}

bool Jellyfish::decodeFile(std::string const &iv, std::string const &key, std::vector<std::istream *> const &in, std::vector<int> const &positions, uint64_t size, std::string const &filename_out)
{
    if (key.size() < crypto::AES256_KeySize || iv.size() < crypto::AES256_IVSize)
    {
        DLOG(WARNING) << "Undersized key or IV";
        return false;
    }
    bool success_a = true, success_b = true;
    pipe_link(
        [&](const char *filename)
    {
        std::ofstream f(filename);
        success_a = Jellyfish::getContentFromCodes(in, positions, N_PARTS, N_CODES, size, f);
    },
        [&](const char *filename)
    {
        try
        {
            byte bkey[crypto::AES256_KeySize], biv[crypto::AES256_IVSize];

            CryptoPP::StringSource(key.substr(0, crypto::AES256_KeySize), true,
                new CryptoPP::ArraySink(bkey, sizeof(bkey)));
            CryptoPP::StringSource(iv.substr(0, crypto::AES256_IVSize), true,
                new CryptoPP::ArraySink(biv, sizeof(biv)));

            CryptoPP::CFB_Mode<CryptoPP::AES>::Decryption decryptor(bkey, sizeof(bkey), biv);
            CryptoPP::FileSource(filename, true,
                new CryptoPP::StreamTransformationFilter(decryptor,
                new CryptoPP::Gunzip(
                new CryptoPP::FileSink(filename_out.c_str(), true))));
        }
        catch (...)
        {
            success_b = false;
        }
    });
    if (!success_a || !success_b)
        unlink(filename_out.c_str());
    return success_a && success_b;
}

