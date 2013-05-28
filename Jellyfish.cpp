#include "Jellyfish.h"

JellyfishReturnCode Jellyfish::login(std::string const &login, std::string const &password)
{
  JellyNodePtr client_node(new JellyNode);
  client_node->Init(static_cast<uint8_t>(_jelly_conf.thread_count),
    mk::KeyPairPtr(), mk::MessageHandlerPtr(), true, _jelly_conf.k,
    _jelly_conf.alpha, _jelly_conf.beta, _jelly_conf.mean_refresh_interval);
  client_node->Start(_jelly_conf.booststrap_contacts, _jelly_conf.ports);

  Key key = getKey(tUser, login);
  FindValueReturns returns;
  Synchronizer<FindValueReturns> sync(returns);
  client_node->node()->FindValue(key, PrivateKeyPtr(), sync);
  sync.wait();

  if (returns.return_code != transport::kSuccess || returns.values_and_signatures.size() != 1)
    return jNoSuchUser;
  UserData user_data = serialize_cast<UserData>(returns.values_and_signatures[0].first);
  std::string crypt_key_iv;
  maidsafe::common::SecurePassword(password, user_data.salt, user_data.pin, &crypt_key_iv);
  std::string iv = crypt_key_iv.substr(0, AES256_IVSize);
  std::string crypt_key = crypt_key_iv.substr(AES256_IVSize, AES256_KeySize);
  std::string private_key = SymmDecrypt(user_data.private_key, crypt_key, iv);
  client_node->Stop();

  asymm::PrivateKey private;
  asymm::DecodePrivateKey(private_key, &private);
  asymm::PublicKey public(private);
  std::string str_public;
  asymm::EncodePublicKey(public, &str_public);
  if (user_data.public_key != str_public)
    return jBadPassword;
  _login = login;
  _keys.reset(new KeyPair);
  _keys->private_key = private;
  _keys->public_key = public;
  _keys->identity = getNodeIdUser(login);

  _jelly_node.reset(new JellyNode);
  client_node->Init(static_cast<uint8_t>(_jelly_conf.thread_count),
    _keys, mk::MessageHandlerPtr(), false, _jelly_conf.k,
    _jelly_conf.alpha, _jelly_conf.beta, _jelly_conf.mean_refresh_interval);
  client_node->Start(_jelly_conf.booststrap_contacts, _jelly_conf.ports);
  _logged_in = true;
  return jSuccess;
}

#define UUID_BYTES (128/8)

std::string Jellyfish::getNodeIdUser(std::string login)
{
  std::string config_path; // This part won't work on Windows...
  const char *home_env = getenv("HOME");
  if (home_env)
    config_path = home_env;
  else
  {
    char buffer[4096];
    struct passwd pw;
    struct passwd *pwp;
    getpwuid_r(getuid(), &pw, buffer, 4096, &pwp);
    if (!pwp)
      throw RuntimeError("Couldn't find home directory");
    config_path = pw.pw_dir;
  }
  config_path += "/.jellyfish/";
  config_path += login;
  boost::filesystem::create_directories(config_path);
  config_path += "/device_id";
  std::ifstream f(config_path);
  std::string uuid;
  uuid.resize(UUID_BYTES);
  f.read(&uuid[0], UUID_BYTES);
  if (f.gcount() == UUID_BYTES)
    return crypto::Hash<crypto::SHA512>(uuid);
  uuid = SRandomString(UUID_BYTES);
  std::ofstream o(config_path);
  o.write(&uuid[0], UUID_BYTES);
  return crypto::Hash<crypto::SHA512>(uuid);
}

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

Key getKey(Jellyfish::Table t, std::string const &key)
{
  std::string table_name;
  switch (t)
  {
    case tUser:
    table_name = "user";
    default:
    throw RuntimeError("Bad table in DHT: " + lexical_cast<std::string>(t));
  }
  return Key(crypto::Hash<crypto::SHA512>(table_name + std::string(":") + key));
}

void PrintNodeInfo(const Contact &contact) {
  ULOG(INFO)
      << boost::format("Node ID:   %1%")
                       % contact.node_id().ToStringEncoded(NodeId::kBase64);
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