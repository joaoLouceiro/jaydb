#include "libjdb/types.hpp"
#include <libjdb/breakpoint_site.hpp>

namespace {
auto get_next_id() {
    static jdb::breakpoint_site::id_type id = 0;
    return ++id;
}
} // namespace
//
jdb::breakpoint_site::breakpoint_site(process &proc, virt_addr address)
    : process_{&proc}, address_{address}, is_enabled_{false}, saved_data_{} {
    id_ = get_next_id();
}
