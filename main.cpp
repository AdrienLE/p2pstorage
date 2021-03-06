#include "JellyInclude.h"

#include <signal.h>

#include "Commands.h"
#include "Jellyfish.h"

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
    signal(SIGPIPE, SIG_IGN);
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
        std::string ip("127.0.0.1");
        std::string login;
        std::string create;
        int storage = -1;
        JellyfishConfig jelly_config;
//        int refresh_interval = jelly_config.mean_refresh_interval;
        po::options_description options_description("Options");
        options_description.add_options()
            ("help,h", "Print options.")
            ("version,V", "Print program version.")
            ("logfile,l", po::value(&logfile), "Path of log file.")
            ("verbose,v", po::bool_switch(), "Verbose logging to console and file.")
            ("first_node,f", po::bool_switch(), "Start the node as the first one of"
             " a new network.")
            ("port,p", po::value<PortRange>(&port_range)->multitoken(),
             "Local listening port/port-range to start non-client type node."
             "Use auto for any port.")
            ("bootstrap,b", po::value<std::string>
             (&bootstrap_file)->default_value(bootstrap_file),
             "Path to XML file with bootstrap nodes.")
            ("alpha,a", po::value(&jelly_config.alpha)->default_value(jelly_config.alpha),
             "Kademlia alpha; parallel level of Find RPCs.")
            ("beta", po::value(&jelly_config.beta)->default_value(jelly_config.beta),
             "Kademlia beta; number of returned Find RPCs required to start a "
             "subsequent iteration.")
            ("login", po::value<std::string>(&login)->default_value(login), "Login name (not necessary)")
            ("create", po::value<std::string>(&create)->default_value(create), "Create account with login (not necessary)")
            ("init_storage", po::value<int>(&storage)->default_value(storage), "Init storage (not necessary, need create)")
            ("thread_count", po::value(&jelly_config.thread_count)->default_value(jelly_config.thread_count),
             "Number of worker threads.");
//            ("refresh_interval,r",
//             po::value(&refresh_interval)->default_value(refresh_interval),
//             "Average time between value refreshes (in seconds).");
        
        po::variables_map variables_map;
        po::store(po::parse_command_line(argc, argv, options_description),
                  variables_map);
                
        if (variables_map.count("help")) {
            std::cout << options_description << std::endl;
            return 0;
        }
        
        if (variables_map.count("version")) {
            std::cout << "Jellyfish "
            << JELLYFISH_VERSION
            << std::endl;
            return 0;
        }
        
        //    ConflictingOptions(variables_map, "upnp", "port_fw");
        //    ConflictingOptions(variables_map, "first_node", "bootstrap_file");
        
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
        
        bool first_node(variables_map["first_node"].as<bool>());
        fs::path bootstrap_file_path(bootstrap_file);
        if (variables_map.count("bootstrap")) {
            bootstrap_file_path =
            fs::path(variables_map["bootstrap"].as<std::string>());
        }
        std::vector<maidsafe::dht::Contact> bootstrap_contacts;
        if (!ReadContactsFromFile(bootstrap_file_path, &bootstrap_contacts) && !first_node) {
            return 1;
        }
        if (bootstrap_contacts.empty() && !first_node) {
            LOG(ERROR) << "No contacts found in bootstrap contacts file.";
            return 1;
        }
        if (variables_map.count("create")) {
            create = variables_map["create"].as<std::string>();
        }
        if (variables_map.count("login")) {
            login = variables_map["login"].as<std::string>();
        }
        if (variables_map.count("init_storage")) {
            storage = variables_map["init_storage"].as<int>();
        }

        jelly_config.bootstrap_contacts = bootstrap_contacts;

        jelly_config.thread_count = variables_map["thread_count"].as<size_t>();

        jelly_config.ports = std::pair<uint16_t, uint16_t>(port_range.first, port_range.second);

        if (first_node)
        {
            Jellyfish jelly(jelly_config);
            jelly.runInitNode(bootstrap_file_path);
            return mk::kSuccess;
        }

        ULOG(INFO) << "create: " << create << " login: " << login << " storage: " << storage;

        Commands commands(jelly_config, login, create, storage);
        commands.Run();
    }
    catch(const std::exception &e) {
        ULOG(ERROR) << "Error: " << e.what();
        return mk::kGeneralError;
    }
    return mk::kSuccess;
}


// JellyNodePtr jelly_node(new JellyNode);
// ULOG(INFO) << "Creating node...";
// demo_node->Init(static_cast<uint8_t>(thread_count), mk::KeyPairPtr(),
//                 mk::MessageHandlerPtr(), false, k, alpha, beta,
//                 mean_refresh_interval);
// std::pair<uint16_t, uint16_t> ports(port_range.first, port_range.second);
// int result = jelly_node->Start(bootstrap_contacts, ports);

// if (first_node)
//   demo_node->node()->GetBootstrapContacts(&bootstrap_contacts);

// WriteContactsToFile(bootstrap_file_path, &bootstrap_contacts);

// if (result != mk::kSuccess) {
//   ULOG(ERROR) << "Node failed to join the network with return code "
//               << result << " ("
//               << ReturnCode2String(mk::ReturnCode(result)) << ")";
//   demo_node->Stop(nullptr);
//   return result;
// }

// PrintNodeInfo(demo_node->node()->contact());
