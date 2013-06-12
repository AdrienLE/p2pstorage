#include "JellyInclude.h"

#include "JellyfishInternal.h"

#include "Jellyfish.h"

#ifdef __APPLE__
#define aligned_alloc(a, b) malloc(b)
#endif

namespace mt = maidsafe::transport;
namespace asymm = maidsafe::rsa;
namespace crypto = maidsafe::crypto;

bool Jellyfish::contactServer(maidsafe::dht::Contact const &contact, boost::function<bool (JellyInternalClient &)> fct, bool raise, bool log)
{
    static FILE *nullfile;
    if (!nullfile)
        nullfile = fopen("/dev/null", "w");
    FILE *err = stderr;
    try
    {
        stderr = nullfile;
        boost::shared_ptr<apache::thrift::transport::TSocket> socket(new apache::thrift::transport::TSocket(contact.endpoint().ip.to_string(), contact.endpoint().port + 1));
        boost::shared_ptr<apache::thrift::transport::TBufferedTransport> transport(new apache::thrift::transport::TBufferedTransport(socket));
        boost::shared_ptr<apache::thrift::protocol::TBinaryProtocol> protocol(new apache::thrift::protocol::TBinaryProtocol(transport));
        transport->open();
        stderr = err;
        JellyInternalClient client(protocol);
        return fct(client);
    }
    catch (std::exception const &e)
    {
        stderr = err;
        if (log)
            ULOG(WARNING) << "Exception in connecting server: " << e.what();
        if (raise)
            throw;
        return false;
    }
    catch (...)
    {
        stderr = err;
        if (raise)
            throw;
        return false;
    }
}

mk::Key Jellyfish::getKey(Table t, std::string const &key)
{
    std::string table_name = Table2String(t);
    return mk::Key(crypto::Hash<crypto::SHA512>(table_name + std::string(":") + key));
}

JellyInternalStatus::type Jellyfish::localPrepareAdd( std::string const &id, long long size, ClientProof const &client )
{
    if (!_files_store)
        return JellyInternalStatus::STORAGE_UNITIALIZED;
    ULOG(INFO) << "localPrepareAdd(" << maidsafe::EncodeToHex(id) << ", " << size << ", " << client.user << ")";
    return _files_store->prepareAdd(id, size, client);
}

JellyInternalStatus::type Jellyfish::localAdd( std::string const &salt, std::string const & id, std::string const & file, ClientProof const &client )
{
    if (!_files_store)
        return JellyInternalStatus::STORAGE_UNITIALIZED;
    ULOG(INFO) << "localAdd(" << maidsafe::EncodeToHex(salt) << ", " << maidsafe::EncodeToHex(id) << ", " << maidsafe::EncodeToBase64(file.substr(0, 100)) << ", " << client.user << ")";
    return _files_store->add(salt, id, file, client);
}

JellyInternalStatus::type Jellyfish::localRemove( std::string const & id, ClientProof const & client )
{
    if (!_files_store)
        return JellyInternalStatus::STORAGE_UNITIALIZED;
    ULOG(INFO) << "localRemove(" << maidsafe::EncodeToHex(id) << ", " << client.user << ")";
    return _files_store->remove(id, client);
}

void Jellyfish::hashPart( HashStatus &res, std::string const & id, std::string const & salt, ClientProof const & client )
{
    if (!_files_store)
    {
        res.status = JellyInternalStatus::STORAGE_UNITIALIZED;
        return;
    }
    ULOG(INFO) << "hashPart(" << maidsafe::EncodeToHex(id) << ", " << maidsafe::EncodeToBase64(salt) << ", " << client.user << ")";
    _files_store->hashPart(res, id, salt, client);
}

void Jellyfish::localGetFile(FileStatus& _return, const std::string& id, const ClientProof& client)
{
    if (!_files_store)
    {
        _return.status = JellyInternalStatus::STORAGE_UNITIALIZED;
        return;
    }
    ULOG(INFO) << "localGetFile(" << maidsafe::EncodeToBase64(id) << ", " << client.user << ")";
    _files_store->localGetFile(_return, id, client);
}

bool Jellyfish::storeFileData( File &file )
{
    int store_result;
    {
        for (FileBlockInfo const &b: file.blocks)
            ULOG(INFO) << "Adding file: " << maidsafe::EncodeToBase64(b.hash_id);
        Synchronizer<int> sync_result(store_result);
        _jelly_node->node()->Store(getKey(tFile, file.hash), serialize_cast<std::string>(file), "", boost::posix_time::pos_infin, _private_key_ptr, sync_result);
        sync_result.wait();
        if (store_result != mk::kSuccess)
        {
            ULOG(WARNING) << "Connection error (1): " << mk::ReturnCode2String((mk::ReturnCode) store_result);
            return false;
        }
    }
    {
        Synchronizer<int> sync_result(store_result);
        ULOG(INFO) << maidsafe::EncodeToBase64(file.hash);
        AbbreviatedFile abv;
        abv.hash = file.hash;
        abv.size = file.size;
        abv.relative_path = file.relative_path;
        _jelly_node->node()->Store(getKey(tUserFiles, _login), serialize_cast<std::string>(abv), "", boost::posix_time::pos_infin, _private_key_ptr, sync_result);
        sync_result.wait();
        if (store_result != mk::kSuccess)
        {
            ULOG(WARNING) << "Connection error (2): " << mk::ReturnCode2String((mk::ReturnCode) store_result);
            return false;
        }
    }
    return true;
}

void PrintNodeInfo(const mk::Contact &contact) {
    ULOG(INFO)
    << boost::format("Node ID:   %1%")
    % contact.node_id().ToStringEncoded(mk::NodeId::kBase64);
    ULOG(INFO)
    << boost::format("Node IP:   %1%") % contact.endpoint().ip.to_string();
    ULOG(INFO)
    << boost::format("Node port: %1%") % contact.endpoint().port;
    ULOG(INFO)
    << boost::format("Debug ID:  %1%") % DebugId(contact);
}


// void Commands::Store(const Arguments &args, bool read_from_file) {
//   std::string value;
//   if (read_from_file) {
//     if (args.size() != 3U) {
//       ULOG(ERROR) << "Invalid number of arguments for storefile command.";
//       return demo_node_->asio_service().post(mark_results_arrived_);
//     }
//     if (!ReadFile(args[1], &value) || value.empty()) {
//       ULOG(ERROR) << "File read error for storefile command.";
//       return demo_node_->asio_service().post(mark_results_arrived_);
//     }
//   } else {
//     value = args[1];
//   }

//   int32_t minutes_to_live(0);
//   try {
//     minutes_to_live = boost::lexical_cast<int32_t>(args[2]);
//   }
//   catch(const std::exception &e) {
//     ULOG(ERROR) << "Invalid ttl for storefile command." << e.what();
//     return demo_node_->asio_service().post(mark_results_arrived_);
//   }

//   bptime::time_duration ttl;
//   if (minutes_to_live == -1)
//     ttl = bptime::pos_infin;
//   else
//     ttl = bptime::minutes(minutes_to_live);

//   Key key(args[0], NodeId::kBase64);
//   if (!key.IsValid())
//     key = Key(crypto::Hash<crypto::SHA512>(args[0]));

//   demo_node_->node()->Store(key, value, "", ttl, null_priv_key_,
//       std::bind(&Commands::StoreCallback, this, args::_1, key, ttl));
// }

// void Commands::StoreCallback(const int &result,
//                              const NodeId &key,
//                              const bptime::time_duration &ttl) {
//   if (result != transport::kSuccess) {
//     ULOG(ERROR) << "Store operation failed with return code: " << result
//                 << " (" << ReturnCode2String(mk::ReturnCode(result)) << ")";
//   } else {
//     ULOG(INFO) <<
//         boost::format("Successfully stored key [ %1% ] with ttl [%2%] min.")
//                       % key.ToStringEncoded(NodeId::kBase64) % ttl.minutes();
//   }
//   demo_node_->asio_service().post(mark_results_arrived_);
// }

// void Commands::FindValue(const Arguments &args, bool write_to_file) {
//   std::string path;
//   if (write_to_file) {
//     if (args.size() != 2U) {
//       ULOG(ERROR) << "Invalid number of arguments for findfile command.";
//       return demo_node_->asio_service().post(mark_results_arrived_);
//     }
//     path = args[1];
//   } else {
//     if (args.size() != 1U) {
//       ULOG(ERROR) << "Invalid number of arguments for findvalue command.";
//       return demo_node_->asio_service().post(mark_results_arrived_);
//     }
//   }

// void Commands::FindValueCallback(FindValueReturns find_value_returns,
//                                  std::string path) {
//   if (find_value_returns.return_code != transport::kSuccess) {
//     ULOG(ERROR) << "FindValue operation failed with return code: "
//                 << find_value_returns.return_code
//                 << " (" << ReturnCode2String(mk::ReturnCode(find_value_returns.return_code)) << ")";
//   } else {
//     ULOG(INFO)
//         << boost::format("FindValue returned: %1% value(s), %2% closest "
//                          "contact(s).") %
//                          find_value_returns.values_and_signatures.size() %
//                          find_value_returns.closest_nodes.size();
//     if (find_value_returns.cached_copy_holder.node_id().String() !=
//         kZeroId) {
//       ULOG(INFO)
//           << boost::format(
//                  "Node holding a cached copy of the value: [ %1% ]")
//                  % find_value_returns.cached_copy_holder.node_id().
//                  ToStringEncoded(NodeId::kBase64);
//     }
//     if (find_value_returns.needs_cache_copy.node_id().String() !=
//         kZeroId) {
//       ULOG(INFO)
//           << boost::format("Node needing a cache copy of the values: [ %1% ]")
//                 % find_value_returns.needs_cache_copy.node_id().
//                 ToStringEncoded(NodeId::kBase64);
//     }
//     // Writing only 1st value
//     if (!find_value_returns.values_and_signatures.empty()) {
//       if (path.empty()) {
//         std::string value(find_value_returns.values_and_signatures[0].first);
//         ULOG(INFO) << "Value: " << value;
//       } else {
//         WriteFile(path, find_value_returns.values_and_signatures[0].first);
//       }
//     }
//   }
//   demo_node_->asio_service().post(mark_results_arrived_);
// }

//   Key key(std::string(args.at(0)), NodeId::kBase64);
//   if (!key.IsValid())
//     key = Key(crypto::Hash<crypto::SHA512>(args[0]));

//   demo_node_->node()->FindValue(key, null_priv_key_,
//       std::bind(&Commands::FindValueCallback, this, args::_1, path));
// }

// void Commands::FindValueCallback(FindValueReturns find_value_returns,
//                                  std::string path) {
//   if (find_value_returns.return_code != transport::kSuccess) {
//     ULOG(ERROR) << "FindValue operation failed with return code: "
//                 << find_value_returns.return_code
//                 << " (" << ReturnCode2String(mk::ReturnCode(find_value_returns.return_code)) << ")";
//   } else {
//     ULOG(INFO)
//         << boost::format("FindValue returned: %1% value(s), %2% closest "
//                          "contact(s).") %
//                          find_value_returns.values_and_signatures.size() %
//                          find_value_returns.closest_nodes.size();
//     if (find_value_returns.cached_copy_holder.node_id().String() !=
//         kZeroId) {
//       ULOG(INFO)
//           << boost::format(
//                  "Node holding a cached copy of the value: [ %1% ]")
//                  % find_value_returns.cached_copy_holder.node_id().
//                  ToStringEncoded(NodeId::kBase64);
//     }
//     if (find_value_returns.needs_cache_copy.node_id().String() !=
//         kZeroId) {
//       ULOG(INFO)
//           << boost::format("Node needing a cache copy of the values: [ %1% ]")
//                 % find_value_returns.needs_cache_copy.node_id().
//                 ToStringEncoded(NodeId::kBase64);
//     }
//     // Writing only 1st value
//     if (!find_value_returns.values_and_signatures.empty()) {
//       if (path.empty()) {
//         std::string value(find_value_returns.values_and_signatures[0].first);
//         ULOG(INFO) << "Value: " << value;
//       } else {
//         WriteFile(path, find_value_returns.values_and_signatures[0].first);
//       }
//     }
//   }
//   demo_node_->asio_service().post(mark_results_arrived_);
// }

// void Commands::GetContact(const Arguments &args) {
//   if (args.size() != 1U) {
//     ULOG(ERROR) << "Invalid number of arguments for getcontact command.";
//     return demo_node_->asio_service().post(mark_results_arrived_);
//   }

//   NodeId node_id(args[0], NodeId::kBase64);
//   if (!node_id.IsValid()) {
//     ULOG(ERROR) << "Invalid Node ID for getcontact command.";
//     return demo_node_->asio_service().post(mark_results_arrived_);
//   }

//   demo_node_->node()->GetContact(node_id,
//       std::bind(&Commands::GetContactsCallback, this, args::_1, args::_2));
// }

// void Commands::GetContactsCallback(const int &result, Contact contact) {
//   if (result != transport::kSuccess) {
//     ULOG(ERROR) << "GetContacts operation failed with error code: " << result
//                 << " (" << ReturnCode2String(mk::ReturnCode(result)) << ")";
//   } else {
//     ULOG(INFO) << "GetContacts operation successfully returned:";
//     PrintNodeInfo(contact);
//   }
//   demo_node_->asio_service().post(mark_results_arrived_);
// }

// void Commands::FindNodes(const Arguments &args, bool write_to_file) {
//   std::string path;
//   if (write_to_file) {
//     if (args.size() != 2U) {
//       ULOG(ERROR) << "Invalid number of arguments for findnodesfile command.";
//       return demo_node_->asio_service().post(mark_results_arrived_);
//     }
//     path = args[1];
//   } else {
//     if (args.size() != 1U) {
//       ULOG(ERROR) << "Invalid number of arguments for findnodes command.";
//       return demo_node_->asio_service().post(mark_results_arrived_);
//     }
//   }

//   NodeId node_id(args[0], NodeId::kBase64);
//   if (!node_id.IsValid()) {
//     ULOG(ERROR) << "Invalid Node ID.";
//     return demo_node_->asio_service().post(mark_results_arrived_);
//   }

//   demo_node_->node()->FindNodes(node_id,
//       std::bind(&Commands::FindNodesCallback, this, args::_1, args::_2, path));
// }

// void Commands::FindNodesCallback(const int &result,
//                                  std::vector<Contact> contacts,
//                                  std::string path) {
//   if (result != transport::kSuccess) {
//     ULOG(ERROR) << "FindNodes operation failed with error code: " << result
//                 << " (" << ReturnCode2String(mk::ReturnCode(result)) << ")";
//   } else {
//     if (path.empty()) {
//       ULOG(INFO) << "FindNodes returned the following " << contacts.size()
//                 << " contact(s):";
//       for (auto it = contacts.begin(); it != contacts.end(); ++it)
//         ULOG(INFO) << (*it).node_id().ToStringEncoded(NodeId::kBase64);
//     } else {
//       std::string content;
//       for (auto it = contacts.begin(); it != contacts.end(); ++it)
//         content += ((*it).node_id().ToStringEncoded(NodeId::kBase64) + "\n");
//       WriteFile(path, content);
//     }
//   }
//   demo_node_->asio_service().post(mark_results_arrived_);
// }


//void lol()
//{
//    std::string s = SRandString(/*rand() % */50000000);
//
//    printf("packet: %d, buf: %d\n", getPacketSize(s.size(), 5), W*8*getPacketSize(s.size(), 5)*5);
//
//    std::istringstream is(s);
//    std::vector<std::ostream *> parts(5), codes(10);
//    std::generate(parts.begin(), parts.end(), [](){return new std::ostringstream();});
//    std::generate(codes.begin(), codes.end(), [](){return new std::ostringstream();});
//    //for (int current = 0; current < 5; ++current)
//    //{
//    //    parts[current] = new std::ofstream(std::string("k_")+boost::lexical_cast<std::string>(current));
//    //}
//    //for (int current = 0; current < 10; ++current)
//    //{
//    //    codes[current] = new std::ofstream(std::string("m_")+boost::lexical_cast<std::string>(current));
//    //}
//    {
//        boost::timer::auto_cpu_timer t;
//        Jellyfish::getPartsCodes(is, s.size(), 5, 10, parts, codes);
//    }
//    std::vector<std::ostream *> streams(parts);
//    std::copy(codes.begin(), codes.end(), std::back_inserter(streams));
//    std::vector<std::istream *> i;
//    std::transform(streams.begin(), streams.end(), std::back_inserter(i), [](std::ostream *o)
//    {
//        auto tmp = new std::istringstream(((std::ostringstream *)o)->str());
//        delete o;
//        return tmp;
//    });
//    std::vector<int> positions;
//    for (int i = 0; i < 5; ++i)
//    {
//        int r;
//        while (true)
//        {
//            r = rand() % 15;
//            bool cont = false;
//            for (int p: positions)
//                if (r == p)
//                    cont = true;
//            if (!cont)
//                break;
//        }
//        positions.push_back(r);
//    }
//    std::sort(positions.begin(), positions.end());
//    printf("%d %d %d %d %d\n", positions[0], positions[1], positions[2], positions[3], positions[4]);
//    std::vector<std::istream *> iparts;
//    std::transform(positions.begin(), positions.end(), std::back_inserter(iparts), [&](int p)
//    {
//        return i[p];
//    });
//    std::ostringstream out;
//    {
//        boost::timer::auto_cpu_timer t;
//        Jellyfish::getContentFromCodes(iparts, positions, 5, 10, s.size(), out);
//    }
//    std::string a = out.str();
//    //printf("%s\n\n%s\n\n", a.c_str(), s.c_str());
//    printf("%lu, %lu\n", a.size(), s.size());
//    if (a != s)
//        printf("Error\n");
//    else
//        printf("Awesome\n");
//
//    for (std::istream *s: i)
//        delete s;
//
//    //printf("%s\n", maidsafe::EncodeToBase64(((std::ostringstream *)streams[disp % 15])->str()).c_str());
//}
//
//int main(int ac, char **av)
//{
//    srand(getpid());
//    int n = 1;
//    if (ac == 2)
//        n = atoi(av[1]);
//    for (int i = 0; i < n; ++i)
//        lol();
//    return 0;
//}

//int main2()
//{
//    //{
//    //    std::string r = SRandString(10000);
//    //    std::ofstream f("a");
//    //    f.write(r.c_str(), r.size());
//    //}
//    std::string k = SRandString(crypto::AES256_KeySize), iv = SRandString(crypto::AES256_IVSize);
//    std::vector<std::ostream *> parts, codes;
//    for (int i = 0; i < 5; ++i)
//    {
//        parts.push_back(new std::ofstream(std::string("k_") + boost::lexical_cast<std::string>(i)));
//        codes.push_back(new std::ofstream(std::string("m_") + boost::lexical_cast<std::string>(i)));
//    }
//    uint64_t size = Jellyfish::encodeFile(iv, k, "kjvdat.txt", parts, codes, [](uint64_t){return true;}, [](const char *, uint64_t){return false;});
//    std::vector<int> positions;
//    for (int i = 0; i < 5; ++i)
//    {
//        int r;
//        while (true)
//        {
//            r = rand() % 10;
//            bool cont = false;
//            for (int p: positions)
//                if (r == p)
//                    cont = true;
//            if (!cont)
//                break;
//        }
//        positions.push_back(r);
//    }
//    std::sort(positions.begin(), positions.end());
//    std::vector<std::istream *> data;
//    for (int i = 0; i < 5; ++i)
//    {
//        data.push_back(new std::ifstream(std::string((positions[i] < N_PARTS) ? "k_" : "m_") +
//            boost::lexical_cast<std::string>((positions[i] < N_PARTS) ? positions[i] : positions[i] - N_PARTS)));
//    }
//    Jellyfish::decodeFile(iv, k, data, positions, size, "b");
//}
