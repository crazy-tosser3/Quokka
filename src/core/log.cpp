#include "core/log.hpp"

#include <iostream>
#include <mutex>

namespace logging {
namespace {

std::mutex g_mutex;
Sink g_sink;
Level g_min_level = Level::Info;

void default_sink(Level level, std::string_view message) {
    auto& out = (level == Level::Warn || level == Level::Error) ? std::cerr : std::cout;
    out << message << std::endl;
}

}

void set_sink(Sink sink) {
    std::lock_guard<std::mutex> lock(g_mutex);
    g_sink = std::move(sink);
}

void set_min_level(Level level) {
    std::lock_guard<std::mutex> lock(g_mutex);
    g_min_level = level;
}

void write(Level level, std::string_view message) {
    std::lock_guard<std::mutex> lock(g_mutex);
    if (level < g_min_level) return;
    if (g_sink) g_sink(level, message);
    else default_sink(level, message);
}

std::string_view to_string(Level level) {
    switch (level) {
    case Level::Debug: return "DEBUG";
    case Level::Info:  return "INFO";
    case Level::Warn:  return "WARN";
    case Level::Error: return "ERROR";
    }
    return "?";
}

}
