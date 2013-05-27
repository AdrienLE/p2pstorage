#pragma once

struct JellyfishConfig
{
  JellyfishConfig() : alpha(3), beta(2), k(4), ports(8000, 65535), bootstrap_contacts(), mean_refresh_interval(1500), thread_count(10) {}

  int alpha;
  int beta;
  int k;
  std::pair<uint16_t, uint16_t> ports;
  std::vector<maidsafe::dht::Contact> bootstrap_contacts;
  bptime::seconds mean_refresh_interval;
  int thread_count;
};
