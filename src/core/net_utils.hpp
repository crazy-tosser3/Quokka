#pragma once

#include <boost/asio/ip/address_v4.hpp>

#include <vector>

// Все IPv4-адреса машины: поиск должен работать на каждом интерфейсе,
// а не только на маршруте по умолчанию (VPN, Docker и несколько сетевых карт)
std::vector<boost::asio::ip::address_v4> local_ipv4_interfaces();

// Поднимает мягкий лимит открытых файлов до жёсткого: у каждого игрового потока свой сокет
void raise_file_limit();
