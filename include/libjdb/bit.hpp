#ifndef JDB_BIT_HPP
#define JDB_BIT_HPP

#include <cstddef>
#include <cstring>
#include <libjdb/types.hpp>
#include <string_view>
#include <vector>

namespace jdb {
template <class To> To from_bytes(const std::byte *bytes) {
    To ret;
    std::memcpy(&ret, bytes, sizeof(To));
    return ret;
}

template <class From> byte128 to_byte128(From src) {
    // The brackets initialize all elements to 0, rather then leaving them uninitialized.
    byte128 ret{};
    std::memcpy(&ret, &src, sizeof(From));
    return ret;
}

template <class From> byte64 to_byte64(From src) {
    byte64 ret{};
    std::memcpy(&ret, &src, sizeof(From));
    return ret;
}

/**
 * Gets the raw bytes of an object @src
 */
template <class From> std::byte *as_bytes(From &from) {
    return reinterpret_cast<std::byte *>(&from);
}

/**
 * Gets the raw bytes of a (const) object @src
 */
template <class From> const std::byte *as_bytes(const From &from) {
    return reinterpret_cast<const std::byte *>(&from);
}

inline std::string_view to_string_view(const std::byte *data, std::size_t size) {
    return {reinterpret_cast<const char *>(data), size};
}

inline std::string_view to_string_view(const std::vector<std::byte> &data) {
    return to_string_view(data.data(), data.size());
}
} // namespace jdb

#endif // !JDB_BIT_HPP
