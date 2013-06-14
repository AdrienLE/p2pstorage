#pragma once

#include "JellyInclude.h"

#include "JellyfishConfig.h"
#include "Jellyfish.h"

class Commands {
 public:
  explicit Commands(JellyfishConfig const &jelly_config, std::string const &login, std::string const &create, int storage) : _jelly(jelly_config), finish_(false), _login(login), _create(create), _storage(storage)
  {
      _timer.stop();
  }
  void Run();

 private:
  typedef std::vector<std::string> Arguments;
  // void Store(const Arguments &args, bool read_from_file);
  // void StoreCallback(const int &result,
  //                    const NodeId &key,
  //                    const bptime::time_duration &ttl);
  // void FindValue(const Arguments &args, bool write_to_file);
  // void FindValueCallback(FindValueReturns find_value_returns, std::string path);
  // void GetContact(const Arguments &args);
  // void GetContactsCallback(const int &result, Contact contact);
  // void FindNodes(const Arguments &args, bool write_to_file);
  // void FindNodesCallback(const int &result,
  //                        std::vector<Contact> contacts,
  //                        std::string path);
  void PrintUsage();
  void ProcessCommand(const std::string &cmdline);

  Jellyfish _jelly;
  boost::timer::cpu_timer _timer;
  bool finish_;
  std::string _login;
  std::string _create;
  int _storage;

  // PrivateKeyPtr null_priv_key_;
  // bool result_arrived_, finish_;
  // boost::mutex wait_mutex_;
  // boost::condition_variable wait_cond_var_;
  // std::function<void()> mark_results_arrived_;
};
