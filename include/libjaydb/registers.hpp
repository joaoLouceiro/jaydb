#ifndef JAYDB_REGISTERS_HPP
#define JAYDB_REGISTERS_HPP

#include <cmath>
#include <cstdint>
#include <libjaydb/register_info.hpp>
#include <libjaydb/types.hpp>
#include <sys/user.h>
#include <variant>

namespace jaydb {
class process;
class registers {
  public:
    // Instance should be unique, so we remove the constructors and copying
    registers() = delete;
    registers(const registers &) = delete;
    registers &operator=(const registers &) = delete;

    using value = std::variant<std::uint8_t, std::uint16_t, std::uint32_t, std::uint64_t,
                               std::int8_t, std::int16_t, std::int32_t, std::int64_t, float, double,
                               long double, byte64, byte128>;
    value read(const register_info &info) const;
    void write(const register_info &info, value val);

    template <class T> T read_by_id_as(register_id id) const {
        return std::get<T>(read(register_info_by_id(id)));
    }

    void write_by_id(register_id id, value val) { write(register_info_by_id(id), val); }

  private:
    // Making process a friend allows us to access it's private members
    friend process;
    registers(process &proc) : proc_(&proc) {}

    // uses the user struct from <sys/user.h>, which has access to the registers
    user data_;
    // Pointer to the parent process allows us to ask it for memory reads.
    process *proc_;
};
} // namespace jaydb
#endif // !JAYDB_REGISTERS_HPP
