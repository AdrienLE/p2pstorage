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

#include "JellyInclude.h"

#include "Commands.h"

#include <iostream>  // NOLINT

namespace args = std::placeholders;
namespace fs = boost::filesystem;

using namespace maidsafe;


void Commands::Run() {
  _timer.start();
  if (_login != "")
      _jelly.login(_login, "password");
  else if (_create != "")
  {
      _jelly.createAccount(_create, "password");
      if (_storage != -1)
          _jelly.initStorage(std::string("../Storage/") + _create, _storage);
  }

  PrintUsage();
  while (!finish_ && std::cin.good()) {
    std::cout << "Jellyfish (" << _jelly.login() << ") > ";
    std::string cmdline;
    std::getline(std::cin, cmdline);
    {
      ProcessCommand(cmdline);
    }
  }
}

void Commands::PrintUsage() {
  ULOG(INFO) << "\thelp                              Print options.";
  ULOG(INFO) << "\tlogin <login> <password>          Login (do this first).";
  ULOG(INFO) << "\tcreate <login> <password>         Create (do this first).";
  ULOG(INFO) << "\tinit_storage <path> <size>        Initialize storage (very important).";
  ULOG(INFO) << "\tput <path> <unique_name>          Add file with unique name.";
  ULOG(INFO) << "\tls                                List files (unique names and sizes).";
  ULOG(INFO) << "\tget <unique_name> <path>          Get file.";
  ULOG(INFO) << "\tcpu                               Get CPU % since start.";
  ULOG(INFO) << "\texit                              Stop the node and exit.";
  ULOG(INFO) << "\nSizes are 2^<size>GB.";
}

void Commands::ProcessCommand(const std::string &cmdline) {
  if (cmdline.empty()) {
    return;
  }

  std::string cmd;
  Arguments args;
  try {
    boost::char_separator<char> sep(" ");
    boost::tokenizer<boost::char_separator<char>> tok(cmdline, sep);
    for (auto it = tok.begin(); it != tok.end(); ++it) {
      if (it == tok.begin())
        cmd = *it;
      else
        args.push_back(*it);
    }
  }
  catch(const std::exception &e) {
    ULOG(ERROR) << "Error processing command: " << e.what();
      return;
  }

  bool good_size = false;

  if (cmd == "help") {
    PrintUsage();
    good_size = true;
  }
  else if (cmd == "login") {
    if (args.size() == 2)
    {
        JellyfishReturnCode ret = _jelly.login(args[0], args[1]);
        if (ret != jSuccess)
            ULOG(ERROR) << "Login error: " << JellyfishReturnCode2String(ret);
        good_size = true;
    }
  }
  else if (cmd == "create") {
      if (args.size() == 2)
      {
          JellyfishReturnCode ret = _jelly.createAccount(args[0], args[1]);
          if (ret != jSuccess)
              ULOG(ERROR) << "Account creation error: " << JellyfishReturnCode2String(ret);
          good_size = true;
      }
  }
  else if (cmd == "init_storage") {
      if (args.size() == 2)
      {
          JellyfishReturnCode ret = _jelly.initStorage(args[0], boost::lexical_cast<uint64_t>(args[1]));
          if (ret != jSuccess)
              ULOG(ERROR) << "Storage initialization error: " << JellyfishReturnCode2String(ret);
          good_size = true;
      }
  }
  else if (cmd == "put") {
      if (args.size() == 2)
      {
          JellyfishReturnCode ret = _jelly.addFile(args[0], args[1]);
          if (ret != jSuccess)
              ULOG(ERROR) << "Add file error: " << JellyfishReturnCode2String(ret);
          good_size = true;
      }
  }
  else if (cmd == "ls") {
      if (args.size() == 0)
      {
          std::set<AbbreviatedFile> files;
          JellyfishReturnCode ret = _jelly.listFiles(files);
          if (ret != jSuccess)
              ULOG(ERROR) << "ls error: " << JellyfishReturnCode2String(ret);
          std::string::size_type max_size = 0;
          for (AbbreviatedFile const &fi: files)
          {
              max_size = std::max(max_size, fi.relative_path.size());
          }
          for (AbbreviatedFile const &fi: files)
          {
              printf("%*s\t%lu\n", (int)max_size, fi.relative_path.c_str(), fi.size);
          }
          fflush(stdout);
          good_size = true;
      }
  }
  else if (cmd == "get")
  {
      if (args.size() == 2)
      {
          JellyfishReturnCode ret = _jelly.getFile(args[0], args[1]);
          if (ret != jSuccess)
              ULOG(ERROR) << "Get error: " << JellyfishReturnCode2String(ret);
          good_size = true;
      }
  }
  else if (cmd == "cpu")
  {
      if (args.size() == 0)
      {
          boost::timer::cpu_times t = _timer.elapsed();
          printf("CPU usage: %.2f\n", ((double)t.user * 100) / t.wall);
          good_size = true;
      }
  }
  else if (cmd == "pid")
  {
      if (args.size() == 0)
      {
          ULOG(INFO) << getpid();
          good_size = true;
      }
  }
  // else if (cmd == "getinfo") {
  //   PrintNodeInfo(demo_node_->node()->contact());
  //   demo_node_->asio_service().post(mark_results_arrived_);
  // }
  // } else if (cmd == "getcontact") {
  //   GetContact(args);
  // } else if (cmd == "storefile") {
  //   Store(args, true);
  // } else if (cmd == "storevalue") {
  //   Store(args, false);
  // } else if (cmd == "findvalue") {
  //   FindValue(args, false);
  // } else if (cmd == "findfile") {
  //   FindValue(args, true);
  // } else if (cmd == "findnodes") {
  //   FindNodes(args, false);
  // } else if (cmd == "findnodesfile") {
  //   FindNodes(args, true);
  // }
  else if (cmd == "exit") {
    ULOG(INFO) << "Exiting application...";
    finish_ = true;
    good_size = true;
  }
  else {
    ULOG(ERROR) << "Invalid command: " << cmd;
    return;
  }
  if (!good_size)
    ULOG(ERROR) << "Bad number of arguments. Use help.";
}



//void Commands::PrintRpcTimings() {
////  rpcprotocol::RpcStatsMap rpc_timings(chmanager_->RpcTimings());
////  ULOG(INFO) << boost::format("Calls  RPC Name  %40t% min/avg/max\n");
////  for (rpcprotocol::RpcStatsMap::const_iterator it = rpc_timings.begin();
////       it != rpc_timings.end();
////       ++it) {
////  ULOG(INFO) << boost::format("%1% : %2% %40t% %3% / %4% / %5% \n")
////           % it->second.Size()
////           % it->first.c_str()
////           % it->second.Min()  // / 1000.0
////           % it->second.Mean()  // / 1000.0
////           % it->second.Max();  // / 1000.0;
////  }
//}

//void Commands::MarkResultArrived() {
//  boost::mutex::scoped_lock lock(wait_mutex_);
//  result_arrived_ = true;
//  wait_cond_var_.notify_one();
//}
