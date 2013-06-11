#pragma once

#include <stdio.h>
#include <boost/function.hpp>
#include <boost/thread.hpp>
#include <sys/types.h>
#include <sys/stat.h>

#include "maidsafe/common/crypto.h"

template<class F1, class F2>
void pipe_link(F1 f1, F2 f2, bool real_file = false)
{
    std::string r = maidsafe::RandomString(16);
    r = maidsafe::EncodeToBase32(r);
    r = std::string("/tmp/jelly_pipe_") + r;
    if (!real_file)
    {
        if (mkfifo(r.c_str(), S_IRUSR| S_IWUSR) == -1)
        {
            fprintf(stderr, "Can't create FIFO in /tmp.\nExiting...\n");
            exit(1);
        }
    }
    boost::thread t([&]() {f1(r.c_str());});
    if (real_file)
        t.join();
    f2(r.c_str());
    if (!real_file)
        t.join();
    unlink(r.c_str());
}
