/* Copyright (c) 2010 maidsafe.net limited
All rights reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

    * Redistributions of source code must retain the above copyright notice,
    this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright notice,
    this list of conditions and the following disclaimer in the documentation
    and/or other materials provided with the distribution.
    * Neither the name of the maidsafe.net limited nor the names of its
    contributors may be used to endorse or promote products derived from this
    software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include <signal.h>
#include <memory>
#include <iostream>  //  NOLINT
#include "boost/program_options.hpp"
#include "boost/filesystem/fstream.hpp"
#include "boost/filesystem.hpp"
#include "boost/lexical_cast.hpp"
#include "maidsafe/dht/log.h"
#include "maidsafe/dht/node-api.h"
#include "maidsafe/dht/node_impl.h"
#include "maidsafe/dht/benchmark/operations.h"

namespace po = boost::program_options;

namespace test_benchmark {
  static const uint16_t K = 16;
}  // namespace test_benchmark

class JoinCallback {
 public:
  JoinCallback() : result_arrived_(false), success_(false) {}
  void Callback(const std::string &/*result*/) {
//    maidsafe::GeneralResponse msg;
//    if (!msg.ParseFromString(result))
      success_ = false;
//    else
//      success_ = (msg.result());
    result_arrived_ = true;
  }
  bool result_arrived() const { return result_arrived_; }
  bool success() const { return success_; }
 private:
  bool result_arrived_, success_;
};

void conflicting_options(const po::variables_map& vm, const char* opt1,
    const char* opt2) {
  if (vm.count(opt1) && !vm[opt1].defaulted()
      && vm.count(opt2) && !vm[opt2].defaulted())
    throw std::logic_error(std::string("Conflicting options '")  + opt1 +
        "' and '" + opt2 + "'.");
}

// Function used to check that if 'for_what' is specified, then
// 'required_option' is specified too.
void option_dependency(const po::variables_map& vm,
    const char* for_what, const char* required_option) {
  if (vm.count(for_what) && !vm[for_what].defaulted())
    if (vm.count(required_option) == 0 || vm[required_option].defaulted())
      throw std::logic_error(std::string("Option '") + for_what
          + "' requires option '" + required_option + "'.");
}

bool kadconfig_empty(const std::string &/*path*/) {
//  maidsafe::KadConfig kadconfig;
//  try {
//    boost::filesystem::ifstream input(path.c_str(),
//                                      std::ios::in | std::ios::binary);
//    if (!kadconfig.ParseFromIstream(&input)) {;
//      return true;
//    }
//    input.close();
//    if (kadconfig.contact_size() == 0)
//      return true;
//  }
//  catch(const std::exception &) {
//    return true;
//  }
  return false;
}

bool write_to_kadconfig(const std::string & path,
    const std::string &/*node_id*/, const std::string &/*ip*/,
    const uint16_t &/*port*/, const std::string &/*local_ip*/,
    const uint16_t &/*local_port*/) {
//  maidsafe::KadConfig kadconfig;
//  try {
//    maidsafe::KadConfig::Contact *ctc = kadconfig.add_contact();
//    ctc->set_ip(ip);
//    ctc->set_node_id(node_id);
//    ctc->set_port(port);
//    ctc->set_local_ip(local_ip);
//    ctc->set_local_port(local_port);
//    boost::filesystem::fstream output(path.c_str(), std::ios::out |
//                                      std::ios::trunc | std::ios::binary);
//    if (!kadconfig.SerializeToOstream(&output)) {
//      output.close();
//      return false;
//    }
//    output.close();
//  }
//    catch(const std::exception &) {
//    return false;
//  }
  return boost::filesystem::exists(path);
}

int main(int argc, char **argv) {
  try {
    std::string logpath, kadconfigpath, bs_ip, bs_id, configfile,
        bs_local_ip, thisnodekconfigpath, idpath;
    uint16_t bs_port(0), bs_local_port(0), port(0);
    int iterations(5), max_nodes(5);
    po::options_description desc("Options");
    desc.add_options()
      ("help,h", "Print options information and exit.")
      ("logfilepath,l", po::value(&logpath), "Path of logfile")
      ("verbose,v", po::bool_switch(), "Print log to console.")
      ("kadconfigfile,k",
        po::value(&kadconfigpath)->default_value(kadconfigpath),
        "Complete pathname of kadconfig file. Default is Node<port>/."
        "kadconfig")
      ("port,p", po::value(&port)->default_value(port),
        "Local port to start node.  Default is 0, that starts in random port.")
      ("bs_ip", po::value(&bs_ip), "Bootstrap node ip.")
      ("bs_port", po::value(&bs_port), "Bootstrap node port.")
      ("bs_local_ip", po::value(&bs_local_ip), "Bootstrap node local ip.")
      ("bs_local_port", po::value(&bs_local_port), "Bootstrap node local port.")
      ("bs_id", po::value(&bs_id), "Bootstrap node id.")
      ("upnp", po::bool_switch(), "Use UPnP for Nat Traversal.")
      ("port_fw", po::bool_switch(), "Manually port forwarded local port.")
      ("id_list", po::value(&idpath),
        "List of nodes' IDs in the network, for lookup operations.")
      ("iterations,i", po::value(&iterations)->default_value(iterations),
        "Number of repetitions per Kad operation.")
      ("max_nodes", po::value(&max_nodes)->default_value(max_nodes),
        "Maximum number of nodes taken from id_list for Kad operations.");
      // TODO(Team#5#): 2010-04-19 - options: disable benchmarks, delay, sizes
    po::variables_map vm;
    po::store(po::parse_command_line(argc, argv, desc), vm);
    if (vm.count("help")) {
      DLOG(INFO) << desc << "\n";
      return 0;
    }
    option_dependency(vm, "bs_id", "bs_ip");
    option_dependency(vm, "bs_ip", "bs_id");
    option_dependency(vm, "bs_id", "bs_port");
    option_dependency(vm, "bs_port", "bs_id");
    option_dependency(vm, "bs_id", "bs_local_ip");
    option_dependency(vm, "bs_id", "bs_local_port");
    option_dependency(vm, "bs_local_ip", "bs_id");
    option_dependency(vm, "bs_local_port", "bs_id");
    option_dependency(vm, "max_nodes", "id_list");
    conflicting_options(vm, "upnp", "port_fw");
    conflicting_options(vm, "verbose", "logfilepath");

    // checking if path of kadconfigfile exists
    if (vm.count("kadconfigfile")) {
      kadconfigpath = vm["kadconfigfile"].as<std::string>();
      boost::filesystem::path kadconfig(kadconfigpath);
      if (!boost::filesystem::exists(kadconfig.parent_path())) {
        try {
          boost::filesystem::create_directories(kadconfig.parent_path());
          if (!vm.count("bs_id")) {
            printf("No bootstrapping info.\n");
            return 1;
          }
        }
        catch(const std::exception &) {
          if (!vm.count("bs_id")) {
            printf("No bootstrapping info.\n");
            return 1;
          }
        }
      } else {
        if (kadconfig_empty(kadconfigpath) && !vm.count("bs_id")) {
          printf("No bootstrapping info.\n");
          return 1;
        }
      }
    } else {
      if (!vm.count("bs_id")) {
        printf("No bootstrapping info.\n");
        return 1;
      }
    }

    // setting log
#ifndef HAVE_GLOG
    std::string FLAGS_log_dir;
#endif
    if (vm.count("logfilepath")) {
#ifdef HAVE_GLOG
      try {
        if (!boost::filesystem::exists(vm["logfilepath"].as<std::string>()))
          boost::filesystem::create_directories(
              vm["logfilepath"].as<std::string>());
        FLAGS_log_dir = vm["logfilepath"].as<std::string>();
      }
      catch(const std::exception &e) {
        printf("Error creating directory for log path: %s\n", e.what());
        printf("Logfile going to default dir (/tmp)\n");
      }
#endif
    } else {
      FLAGS_logtostderr = vm["verbose"].as<bool>();
    }
    maidsafe::InitLogging(argv[0]);

/*
    // Starting transport on port
    port = vm["port"].as<uint16_t>();
    boost::shared_ptr<transport::UdtTransport> tra(new transport::UdtTransport);
    transport::TransportCondition tc;
    tra->StartListening("", port, &tc);
    if (transport::kSuccess != tc) {
      printf("Node failed to start transport on port %d.\n", port);
      return 1;
    }
    boost::shared_ptr<rpcprotocol::ChannelManager> cm(
        new rpcprotocol::ChannelManager(tra));
    if (0 != cm->Start()) {
      printf("Node failed to start ChannelManager.\n");
      tra->StopListening(port);
      return 1;
    }
    kademlia::NodeConstructionParameters kcp;
    kcp.alpha = kademlia::kAlpha;
    kcp.beta = kademlia::kBeta;
    kcp.k = test_benchmark::K;
    kcp.port_forwarded = false;
    kcp.refresh_time = kademlia::kRefreshTime;
    kcp.use_upnp = false;
    kcp.type = kademlia::CLIENT;
    kcp.port = port;
    boost::shared_ptr<kademlia::Node> node(new kademlia::Node(cm, tra, kcp));

    // setting kadconfig file if it was not in the options
    if (kadconfigpath.empty()) {
      kadconfigpath = "NodeInfo" + boost::lexical_cast<std::string>(port);
      boost::filesystem::create_directories(kadconfigpath);
      kadconfigpath += "/.kadconfig";
    }

    // Joining the node to the network
    JoinCallback callback;
    node->Join(kadconfigpath,
               boost::bind(&JoinCallback::Callback, &callback, _1));
    while (!callback.result_arrived())
      Sleep(boost::posix_time::milliseconds(500));
    // Checking result of callback
    if (!callback.success()) {
      printf("Node failed to join the network.\n");
      tra->StopListening(port);
      cm->Stop();
      return 1;
    }

    // get node IDs from text file
    std::vector<kademlia::NodeId> nodes;
    if (vm.count("id_list")) {
      try {
        boost::filesystem::ifstream idf(vm["id_list"].as<std::string>(),
                                        std::ios::in);
        while (!idf.eof()) {
          char line[150];
          idf.getline(line, sizeof(line));
          try {
            kademlia::NodeId id(line, kademlia::NodeId::kHex);
            nodes.push_back(id);
          }
          catch(const std::exception &) {
          }
        }
        idf.close();
      }
      catch(const std::exception &) {
      }
    }

    size_t nodes_count = nodes.size();
    if (nodes_count > static_cast<size_t>(max_nodes) && max_nodes > 0)
      nodes.resize(max_nodes);

    printf("Read %d node IDs from list, running tests on %d of them.\n",
           nodes_count, nodes.size());

    benchmark::Operations ops(node);

    printf("\n[ Testing GetNodeContactDetails and Ping ]\n");
    ops.TestFindAndPing(nodes, iterations);

    if (nodes_count >= test_benchmark::K * kademlia::kMinSuccessfulPecentageStore) {
      printf("\n[ Testing StoreValue and FindValue (unsigned) ]\n");
      ops.TestStoreAndFind(nodes, iterations, false);
      printf("\n[ Testing StoreValue and FindValue (signed) ]\n");
      ops.TestStoreAndFind(nodes, iterations, true);
    } else {
      printf("\n[ Skipping tests of StoreValue and FindValue ]\n");
    }

    node->Leave();
    tra->StopListening(port);
    cm->Stop();
    printf("\nNode stopped successfully.\n\n");
    benchmark::Operations::PrintRpcTimings(cm->RpcTimings());
*/
  }
  catch(const std::exception &e) {
    printf("Error: %s\n", e.what());
    return 1;
  }
  return 0;
}

