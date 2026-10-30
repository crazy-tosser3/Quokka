#pragma once

#include <functional>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>

namespace logging {

enum class Level { Debug, Info, Warn, Error };

using Sink = std::function<void(Level, std::string_view)>;

void set_sink(Sink sink);
void set_min_level(Level level);
void write(Level level, std::string_view message);
std::string_view to_string(Level level);

template <class... Args>
std::string concat(Args&&... args) {
    std::ostringstream out;
    (out << ... << std::forward<Args>(args));
    return out.str();
}

template <class... Args> void debug(Args&&... a) { write(Level::Debug, concat(std::forward<Args>(a)...)); }
template <class... Args> void info(Args&&... a)  { write(Level::Info,  concat(std::forward<Args>(a)...)); }
template <class... Args> void warn(Args&&... a)  { write(Level::Warn,  concat(std::forward<Args>(a)...)); }
template <class... Args> void error(Args&&... a) { write(Level::Error, concat(std::forward<Args>(a)...)); }

}
