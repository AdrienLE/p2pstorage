/* Copyright (c) 2009 maidsafe.net limited
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
#include "boost/filesystem.hpp"
#include "boost/program_options.hpp"

#ifndef __APPLE__
  #include "maidsafe/common/breakpad.h"
#endif
#include "maidsafe/common/crypto.h"
#include "maidsafe/common/utils.h"

#ifdef __MSVC__
#  pragma warning(push)
#  pragma warning(disable: 4127 4244 4267)
#endif
#ifdef __MSVC__
#  pragma warning(pop)
#endif
#include "maidsafe/dht/config.h"
#include "maidsafe/dht/contact.h"
#include "maidsafe/dht/node-api.h"
#include "maidsafe/dht/node_container.h"
#include "maidsafe/dht/node_id.h"
#include "maidsafe/dht/return_codes.h"
#include "maidsafe/dht/version.h"

#include "maidsafe/common/log.h"

#include "Commands.h"

namespace bptime = boost::posix_time;
namespace fs = boost::filesystem;
namespace po = boost::program_options;
namespace mk = maidsafe::dht;
namespace mt = maidsafe::transport;
namespace ma = maidsafe::asymm;

struct PortRange {
  PortRange(uint16_t first, uint16_t second)
      : first(first), second(second) {}
  uint16_t first;
  uint16_t second;
};

namespace {

void ConflictingOptions(const po::variables_map &variables_map,
                        const char *opt1,
                        const char *opt2) {
  if (variables_map.count(opt1) && !variables_map[opt1].defaulted()
      && variables_map.count(opt2) && !variables_map[opt2].defaulted()) {
    throw std::logic_error(std::string("Conflicting options '") + opt1 +
                           "' and '" + opt2 + "'.");
  }
}

// Function used to check that if 'for_what' is specified, then
// 'required_option' is specified too.
void OptionDependency(const po::variables_map &variables_map,
                      const char *for_what,
                      const char *required_option) {
  if (variables_map.count(for_what) && !variables_map[for_what].defaulted()) {
    if (variables_map.count(required_option) == 0 ||
        variables_map[required_option].defaulted()) {
      throw std::logic_error(std::string("Option '") + for_what
                             + "' requires option '" + required_option + "'.");
    }
  }
}

volatile bool ctrlc_pressed(false);

void CtrlCHandler(int /*a*/) {
  ctrlc_pressed = true;
}

mk::Contact ComposeContact(const mk::NodeId &node_id,
                           const mt::Endpoint &endpoint) {
  std::vector<mt::Endpoint> local_endpoints;
  local_endpoints.push_back(endpoint);
  mk::Contact contact(node_id, endpoint, local_endpoints, endpoint, false,
                      false, "", ma::PublicKey(), "");
  return contact;
}

mk::Contact ComposeContactWithKey(
    const mk::NodeId &node_id,
    const mt::Endpoint &endpoint,
    const ma::Keys &crypto_key_pair) {
  std::vector<mt::Endpoint> local_endpoints;
  local_endpoints.push_back(endpoint);
  mk::Contact contact(node_id, endpoint, local_endpoints, endpoint, false,
                      false, node_id.String(), crypto_key_pair.public_key, "");
  return contact;
}

}  // unnamed namespace

void validate(boost::any& v, const std::vector<std::string>& values,
              PortRange*, int) {
  PortRange port_range(0, 0);
  if (values.size() == 1) {
    try {
      std::string arg = boost::lexical_cast<std::string>(values.at(0));
      if (arg.compare("auto") == 0 || arg.compare("AUTO") == 0) {  // auto
        port_range.first = 8000;
        port_range.second = 65535;
      } else if (arg.find("-") != std::string::npos) {  // port range
        boost::char_separator<char> sep("-");
        boost::tokenizer<boost::char_separator<char>> tok(arg, sep);
        auto it = tok.begin();
        port_range.first = boost::lexical_cast<uint16_t>(*it);
        ++it;
        if (it == tok.end()) {
          throw po::validation_error(po::validation_error::invalid_option);
        }
        port_range.second = boost::lexical_cast<uint16_t>(*it);
        ++it;
        if (it != tok.end()) {
          throw po::validation_error(po::validation_error::invalid_option);
        }
      } else {  // specific port
        port_range.first = boost::lexical_cast<uint16_t>(arg);
        port_range.second = boost::lexical_cast<uint16_t>(arg);
      }
    }
    catch(boost::bad_lexical_cast&) {
      throw po::validation_error(po::validation_error::invalid_option);
    }
  } else {
    throw po::validation_error(po::validation_error::invalid_option,
                               "Invalid port or port range");
  }

  if (port_range.first > port_range.second || port_range.first < 8000) {
    throw po::validation_error(po::validation_error::invalid_option,
                               "Invalid port range");
  }
  v = port_range;
}

int main(int argc, char **argv) {
  maidsafe::InitLogging(argv[0]);
#ifndef __APPLE__
  fs::path cur_path = fs::initial_path();
  maidsafe::crash_report::ProjectInfo current_project("MaidSafe-DHT",
                        boost::lexical_cast<std::string>(MAIDSAFE_DHT_VERSION));
#ifdef WIN32
  google_breakpad::ExceptionHandler exception_handler(cur_path.wstring(),
                                        nullptr,
                                        maidsafe::crash_report::DumpCallback,
                                        &current_project,
                                        true);
#else
  google_breakpad::ExceptionHandler exception_handler(cur_path.string(),
                                        nullptr,
                                        maidsafe::crash_report::DumpCallback,
                                        &current_project,
                                        true);
#endif
#endif
  try {
    PortRange port_range(8000, 65535);
    std::string logfile, bootstrap_file("bootstrap_contacts");
    uint16_t k(4), alpha(3), beta(2);
    std::string ip("127.0.0.1");
    uint32_t refresh_interval(3600);
    size_t thread_count(3);
    po::options_description options_description("Options");
    options_description.add_options()
        ("help,h", "Print options.")
        ("version,V", "Print program version.")
        ("logfile,l", po::value(&logfile), "Path of log file.")
        ("verbose,v", po::bool_switch(), "Verbose logging to console and file.")
//        ("kadconfigfile,g",
//          po::value(&kadconfigpath)->default_value(kadconfigpath),
//          "Complete pathname of kadconfig file. Default is Node<port>/."
//          "kadconfig")
        ("client,c", po::bool_switch(), "Start the node as a client node.")
        ("first_node,f", po::bool_switch(), "Start the node as the first one of"
            " a new network.")
//        ("type,t", po::value(&type)->default_value(type),
//            "Type of transport: 0 - TCP (default), 1 - UDP, 2 - Other.")
//        ("port,p", po::value(&listening_port)->default_value(listening_port),
//            "Local listening port of node (applicable to non-client type "
//            "only).")
        ("port,p", po::value<PortRange>(&port_range)->multitoken(),
              "Local listening port/port-range to start non-client type node."
              "Use auto for any port.")
        ("bootstrap,b", po::value<std::string>
            (&bootstrap_file)->default_value(bootstrap_file),
            "Path to XML file with bootstrap nodes.")
        ("k,k", po::value(&k)->default_value(k),
            "Kademlia k; default number of contacts returned from a lookup.")
        ("alpha,a", po::value(&alpha)->default_value(alpha),
            "Kademlia alpha; parallel level of Find RPCs.")
        ("beta", po::value(&beta)->default_value(beta),
            "Kademlia beta; number of returned Find RPCs required to start a "
            "subsequent iteration.")
//        ("upnp", po::bool_switch(), "Use UPnP for Nat Traversal.")
//        ("port_fw", po::bool_switch(), "Manually port forwarded local port.")
//        ("secure", po::bool_switch(),
//            "Node with keys. Can only communicate with other secure nodes")
        ("thread_count", po::value(&thread_count)->default_value(thread_count),
            "Number of worker threads.")
        ("noconsole", po::bool_switch(),
            "Disable access to Kademlia functions (store, findvalue, "
            "findnode, etc.) after node startup.")
//        ("nodeinfopath", po::value(&thisnodekconfigpath),
//        "Writes to this path a kadconfig file (with name .kadconfig) with "
//          "this node's information.")
        ("refresh_interval,r",
            po::value(&refresh_interval)->default_value(refresh_interval / 60),
            "Average time between value refreshes (in minutes).");

    po::variables_map variables_map;
    po::store(po::parse_command_line(argc, argv, options_description),
              variables_map);


    if (variables_map.count("help")) {
      std::cout << options_description << std::endl;
      return 0;
    }

    if (variables_map.count("version")) {
      std::cout << "MaidSafe-DHT "
                << maidsafe::GetMaidSafeVersion(MAIDSAFE_DHT_VERSION)
                << std::endl;
      return 0;
    }

//    ConflictingOptions(variables_map, "upnp", "port_fw");
    ConflictingOptions(variables_map, "client", "noconsole");
    ConflictingOptions(variables_map, "first_node", "bootstrap_file");

    // Set up logging
    if (variables_map["verbose"].as<bool>()) {
      FLAGS_ms_logging_common = google::INFO;
      FLAGS_ms_logging_transport = google::INFO;
      FLAGS_ms_logging_dht = google::INFO;
    } else {
      FLAGS_ms_logging_common = google::FATAL;
      FLAGS_ms_logging_transport = google::FATAL;
      FLAGS_ms_logging_dht = google::FATAL;
    }
    FLAGS_log_prefix = variables_map["verbose"].as<bool>();
    FLAGS_ms_logging_user = google::INFO;
    FLAGS_logtostderr = true;
    if (variables_map.count("logfile")) {
      fs::path log_path;
      try {
        log_path = fs::path(variables_map["logfile"].as<std::string>());
        if (!fs::exists(log_path.parent_path()) &&
            !fs::create_directories(log_path.parent_path())) {
          ULOG(ERROR) << "Could not create directory for log file.";
          log_path = fs::temp_directory_path() / "kademlia_demo.log";
        }
      }
      catch(const std::exception &e) {
        ULOG(ERROR) << "Error creating directory for log file: " << e.what();
        boost::system::error_code error_code;
        log_path = fs::temp_directory_path(error_code) / "kademlia_demo.log";
      }

      ULOG(INFO) << "Log file at " << log_path;
      for (google::LogSeverity severity(google::WARNING);
           severity != google::NUM_SEVERITIES; ++severity) {
        google::SetLogDestination(severity, "");
      }
      google::SetLogDestination(google::INFO, log_path.string().c_str());
      FLAGS_alsologtostderr = true;
    }

    // Set up DemoNode
    bool first_node(variables_map["first_node"].as<bool>());
    fs::path bootstrap_file_path(bootstrap_file);
    if (variables_map.count("bootstrap")) {
      bootstrap_file_path =
          fs::path(variables_map["bootstrap"].as<std::string>());
    }
    std::vector<maidsafe::dht::Contact> bootstrap_contacts;
    if (!first_node) {
      if (!ReadContactsFromFile(bootstrap_file_path, &bootstrap_contacts)) {
         return 1;
      }
      if (bootstrap_contacts.empty()) {
        LOG(ERROR) << "No contacts found in bootstrap contacts file.";
        return 1;
      }
    }

    thread_count = variables_map["thread_count"].as<size_t>();
    if (thread_count > 100) {
      ULOG(WARNING) << "Too many threads.  Setting thread count to 3.";
      thread_count = 3;
    }

    bool client_only_node(variables_map["client"].as<bool>());

//    type = (variables_map["type"].as<int>());
//    if (type > 2) {
//      ULOG(ERROR) << "Invalid transport type.  Choose 0, 1 or 2.";
//      return 1;
//    }


    if (variables_map.count("refresh_interval")) {
      refresh_interval = variables_map["refresh_interval"].as<uint32_t>();
      refresh_interval = refresh_interval * 60;
    } else {
      refresh_interval = 3600;
    }
    bptime::seconds mean_refresh_interval(refresh_interval);

//    bool secure(variables_map["secure"].as<bool>());


    DemoNodePtr demo_node(new DemoNode);
    ULOG(INFO) << "Creating node...";
    demo_node->Init(static_cast<uint8_t>(thread_count), mk::KeyPairPtr(),
                    mk::MessageHandlerPtr(), client_only_node, k, alpha, beta,
                    mean_refresh_interval);
    std::pair<uint16_t, uint16_t> ports(port_range.first, port_range.second);
    int result = demo_node->Start(bootstrap_contacts, ports);

    if (first_node)
      demo_node->node()->GetBootstrapContacts(&bootstrap_contacts);

    WriteContactsToFile(bootstrap_file_path, &bootstrap_contacts);

    if (result != mk::kSuccess) {
      ULOG(ERROR) << "Node failed to join the network with return code "
                  << result;
      demo_node->Stop(nullptr);
      return result;
    }

    PrintNodeInfo(demo_node->node()->contact());

    if (!variables_map["noconsole"].as<bool>()) {
      Commands commands(demo_node);
      commands.Run();
    } else {
      ULOG(INFO) << "===============================";
      ULOG(INFO) << "     Press Ctrl+C to exit.";
      ULOG(INFO) << "===============================";
      signal(SIGINT, CtrlCHandler);
      while (!ctrlc_pressed)
        maidsafe::Sleep(boost::posix_time::seconds(1));
    }
    bootstrap_contacts.clear();
    demo_node->Stop(&bootstrap_contacts);
    ULOG(INFO) << "Node stopped successfully.";
  }
  catch(const std::exception &e) {
    ULOG(ERROR) << "Error: " << e.what();
    return mk::kGeneralError;
  }
  return mk::kSuccess;
}
