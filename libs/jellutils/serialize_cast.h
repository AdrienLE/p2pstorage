#pragma once

#include <string>
#include <sstream>
#include "portable_binary_iarchive.hpp"
#include "portable_binary_oarchive.hpp"

template<typename Target>
struct CastTo
{
  static Target cast(std::string const &src)
  {
  	Target result;
  	std::istringstream is(src);
  	portable_binary_iarchive archive(is);
  	archive >> result;
  	return result;
  }
};

template<>
struct CastTo<std::string>
{
  template<typename Source>
  static std::string cast(Source const &src)
  {
  	std::ostringstream os;
  	portable_binary_oarchive archive(os);
  	archive << src;
  	return os.str();
  }
};

template<typename Target, typename Source>
Target serialize_cast(Source const &src)
{
  return CastTo<Target>::cast(src);
}
