
/*
#pragma once
#include <iostream>
#include <string>
#include <vector>
#include <tuple>
#include <boost/asio.hpp>

class FlowChanger
{
public:

  std::string local_address;

  FlowChanger()
  {
  }

  virtual ~FlowChanger()
  {
  }

  void SetLocalAddress()
  {
    boost::asio::io_service io_service;
    boost::asio::ip::tcp::resolver resolver(io_service);
    boost::asio::ip::tcp::resolver::query query(boost::asio::ip::host_name(), "");

    std::vector<std::tuple<int, std::string>> address_list;

    for (auto it = resolver.resolve(query); it != boost::asio::ip::tcp::resolver::iterator(); it++)
    {
      auto addr = it->endpoint().address();
      if (addr.is_v4())
      {
        address_list.push_back(std::make_tuple(1, addr.to_string()));
      }      
    }

    for (std::string address : address_list) {
      std::cout << address << std::endl;
    }
  }
};

*/