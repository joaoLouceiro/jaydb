#ifndef JAYDB_BREAKPOINT_SITE_HPP
#define JAYDB_BREAKPOINT_SITE_HPP

#include <cstddef>
#include <cstdint>
#include <libjaydb/types.hpp>

namespace jaydb {
class process;

class breakpoint_site {
  public:
    breakpoint_site() = delete;
    breakpoint_site(breakpoint_site &&) = delete;
    breakpoint_site(const breakpoint_site &) = delete;

    using id_type = std::int32_t;
    id_type id() const { return id_; }

    void enable();
    void disable();

    bool is_enabled() const { return is_enabled_; }
    virt_addr address() const { return address_; }

    bool at_address(virt_addr addr) const { return address_ == addr; }
    bool in_range(virt_addr low, virt_addr high) const {
        return low <= address_ and high > address_;
    }

  private:
    breakpoint_site(process &proc, virt_addr adress);
    friend process;

    id_type id_;
    process *process_;
    virt_addr address_;
    bool is_enabled_;
    std::byte saved_data_;
};

} // namespace jaydb

#endif // !JAYDB_BREAKPOINT_SITE_HPP
