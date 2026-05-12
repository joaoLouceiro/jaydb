#include <catch2/catch_test_macros.hpp>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <elf.h>
#include <filesystem>
#include <fmt/base.h>
#include <fstream>
#include <libjaydb/bit.hpp>
#include <libjaydb/error.hpp>
#include <libjaydb/pipe.hpp>
#include <libjaydb/process.hpp>
#include <libjaydb/register_info.hpp>
#include <libjaydb/types.hpp>
#include <regex>
#include <signal.h>
#include <string>
#include <sys/types.h>

using namespace jaydb;

namespace {
bool process_exists(pid_t pid) {
    auto ret = kill(pid, 0);
    return ret != -1 && errno != ESRCH;
}

namespace {
std::int64_t get_section_load_bias(std::filesystem::path path, Elf64_Addr file_address) {
    auto command = std::string("readelf -WS ") + path.string();
    auto pipe = popen(command.c_str(), "r");

    std::regex text_regex(R"(PROGBITS\s+(\w+)\s+(\w+)\s+(\w+))");
    char *line = nullptr;
    std::size_t len = 0;
    while (getline(&line, &len, pipe) != -1) {
        std::cmatch groups;
        if (std::regex_search(line, groups, text_regex)) {
            auto address = std::stol(groups[1], nullptr, 16);
            auto offset = std::stol(groups[2], nullptr, 16);
            auto size = std::stol(groups[3], nullptr, 16);
            if (address <= file_address && file_address < (address + size)) {
                free(line);
                pclose(pipe);
                return address - offset;
            }
        }
        free(line);
        line = nullptr;
    }
    pclose(pipe);
    jaydb::error::send("Could not find dection load bias");
}

std::int64_t get_entry_point_offset(std::filesystem::path path) {
    std::ifstream elf_file(path);

    Elf64_Ehdr header;
    elf_file.read(reinterpret_cast<char *>(&header), sizeof(header));

    auto entry_file_address = header.e_entry;
    auto load_bias = get_section_load_bias(path, entry_file_address);
    return entry_file_address - load_bias;
}

virt_addr get_load_address(pid_t pid, std::int64_t offset) {
    std::ifstream maps("/proc/" + std::to_string(pid) + "/maps");
    std::regex map_regex(R"((\w+)-\w+ ..(.). (\w+))");

    std::string data;
    while (std::getline(maps, data)) {
        std::smatch groups;
        std::regex_search(data, groups, map_regex);

        if (groups[2] == 'x') {
            auto low_range = std::stol(groups[1], nullptr, 16);
            auto file_offset = std::stol(groups[3], nullptr, 16);
            return virt_addr(offset - file_offset + low_range);
        }
    }
    jaydb::error::send("Could not find load address");
}
} // namespace

char get_process_status(pid_t pid) {
    std::ifstream stat("/proc/" + std::to_string(pid) + "/stat");
    std::string data;
    std::getline(stat, data);
    auto index_of_last_parenthesis = data.rfind(')');
    auto index_of_status_indicator = index_of_last_parenthesis + 2;
    return data[index_of_status_indicator];
}
} // namespace

TEST_CASE("process::launch success", "[process]") {
    auto proc = process::launch("yes");
    REQUIRE(process_exists(proc->pid()));
}

TEST_CASE("process::launch no such program", "[process]") {
    REQUIRE_THROWS_AS(process::launch("there_is_no_such_program_here"), error);
}

// So, apparently, the CWD is the one we call ./tests from, so the process::launch path is not
// relative to the tests.cpp file. That means that, if we execute the tests from, say, /build
// (./test/tests), the program will look for /build/targets/run_endlessly, which doesn't exist,
// failing the test.
TEST_CASE("process:attach success", "[process]") {
    auto target = process::launch("test/targets/run_endlessly", false);
    auto proc = process::attach(target->pid());
    REQUIRE(get_process_status(target->pid()) == 't');
}

TEST_CASE("process:attach invalid PID", "[process]") {
    REQUIRE_THROWS_AS(process::attach(0), error);
}

TEST_CASE("process::resume success", "[process]") {
    {
        auto proc = process::launch("test/targets/run_endlessly");
        proc->resume();
        auto status = get_process_status(proc->pid());
        auto success = status == 'R' || status == 'S';
        REQUIRE(success);
    }
    {
        auto target = process::launch("test/targets/run_endlessly", false);
        auto proc = process::attach(target->pid());
        proc->resume();
        auto status = get_process_status(proc->pid());
        auto success = status == 'R' || status == 'S';
        REQUIRE(success);
    }
}

TEST_CASE("process::resume already terminated", "[process]") {
    auto proc = process::launch("test/targets/end_immediately");
    proc->resume();
    proc->wait_on_signal();
    REQUIRE_THROWS_AS(proc->resume(), error);
}

TEST_CASE("Write register works", "[register]") {
    // Our goal is to check, from within a running process, that we can affect the value of a
    // register.
    bool close_on_exec = false;
    jaydb::pipe channel(close_on_exec);

    auto proc = process::launch("test/targets/reg_write", true, channel.get_write());
    channel.close_write();

    proc->resume();
    proc->wait_on_signal();

    // Because we are writing to rsi (where the syscall expects it's first parameter to live)
    // from the debugger's test, printf will send the value we just wrote to the standard out.
    auto &regs = proc->get_registers();
    regs.write_by_id(register_id::rsi, 0xcafecafe);

    proc->resume();
    proc->wait_on_signal();

    auto output = channel.read();
    REQUIRE(to_string_view(output) == "0xcafecafe");

    regs.write_by_id(register_id::mm0, 0xba5eba11);

    proc->resume();
    proc->wait_on_signal();

    output = channel.read();
    REQUIRE(to_string_view(output) == "0xba5eba11");

    regs.write_by_id(register_id::xmm0, 42.42);

    proc->resume();
    proc->wait_on_signal();

    output = channel.read();
    REQUIRE(to_string_view(output) == "42.42");

    // This test is a bit weirder. x87 registers work with their own sort of stack and set of
    // instructions. Getting the value onto the register itself is easy enough:
    regs.write_by_id(register_id::st0, 42.24l);
    // The FSW register is responsible for the Status Word. This tracks the the current size of the
    // FPU stack and reports errors like stack overflows, precision errors, or divisions by zero.
    // Bits 11 through 13 track the top of the stack, which starts at index 0 and goes down,
    // wrapping around to 7. To push the value to the stack, we set these bits to 7 (0b111).
    regs.write_by_id(register_id::fsw, std::uint16_t{0b0011100000000000});
    // The FPU Tag Word register tracks which of the st registers are valid, empty, or have a
    // special value like infinity or NaN. 0b00 is a valid register, 0b11 is invalid.
    regs.write_by_id(register_id::ftw, std::uint16_t{0b0011111111111111});

    proc->resume();
    proc->wait_on_signal();

    output = channel.read();
    REQUIRE(to_string_view(output) == "42.24");
}

TEST_CASE("Read register works", "[register]") {
    auto proc = process::launch("test/targets/reg_read");
    auto &regs = proc->get_registers();

    proc->resume();
    proc->wait_on_signal();

    REQUIRE(regs.read_by_id_as<std::uint64_t>(register_id::r13) == 0xcafecafe);

    proc->resume();
    proc->wait_on_signal();

    REQUIRE(regs.read_by_id_as<std::uint8_t>(register_id::r13b) == 42);

    proc->resume();
    proc->wait_on_signal();

    REQUIRE(regs.read_by_id_as<byte64>(register_id::mm0) == to_byte64(0xba5eba11ull));

    proc->resume();
    proc->wait_on_signal();

    REQUIRE(regs.read_by_id_as<byte128>(register_id::xmm0) == to_byte128(64.125));

    proc->resume();
    proc->wait_on_signal();

    REQUIRE(regs.read_by_id_as<long double>(register_id::st0) == 64.125L);
}

TEST_CASE("Can create breakpoint site", "[breakpoint]") {
    auto proc = process::launch("test/targets/run_endlessly");
    auto &site = proc->create_breakpoint_site(virt_addr{42});
    REQUIRE(site.address().addr() == 42);
}

TEST_CASE("Breakpoint site ids increase", "[breakpoint]") {
    auto proc = process::launch("test/targets/run_endlessly");

    auto &s1 = proc->create_breakpoint_site(virt_addr{42});
    REQUIRE(s1.address().addr() == 42);

    auto &s2 = proc->create_breakpoint_site(virt_addr{43});
    REQUIRE(s2.id() == s1.id() + 1);

    auto &s3 = proc->create_breakpoint_site(virt_addr{44});
    REQUIRE(s3.id() == s1.id() + 2);

    auto &s4 = proc->create_breakpoint_site(virt_addr{45});
    REQUIRE(s4.id() == s1.id() + 3);
}

TEST_CASE("Can find breakpoint site", "[breakpoint]") {
    auto proc = process::launch("test/targets/run_endlessly");
    const auto &cproc = proc;

    proc->create_breakpoint_site(virt_addr{42});
    proc->create_breakpoint_site(virt_addr{43});
    proc->create_breakpoint_site(virt_addr{44});
    proc->create_breakpoint_site(virt_addr{45});

    auto &s1 = proc->breakpoint_sites().get_by_address(virt_addr{44});
    REQUIRE(proc->breakpoint_sites().contains_address(virt_addr{44}));
    REQUIRE(s1.address().addr() == 44);

    auto &cs1 = cproc->breakpoint_sites().get_by_address(virt_addr{44});
    REQUIRE(cproc->breakpoint_sites().contains_address(virt_addr{44}));
    REQUIRE(cs1.address().addr() == 44);

    auto &s2 = proc->breakpoint_sites().get_by_id(s1.id() + 1);
    REQUIRE(proc->breakpoint_sites().contains_id(s1.id() + 1));
    REQUIRE(s2.id() == s1.id() + 1);
    REQUIRE(s2.address().addr() == 45);

    auto &cs2 = proc->breakpoint_sites().get_by_id(cs1.id() + 1);
    REQUIRE(proc->breakpoint_sites().contains_id(cs1.id() + 1));
    REQUIRE(cs2.id() == cs1.id() + 1);
    REQUIRE(cs2.address().addr() == 45);
}

TEST_CASE("Cannot find breakpoint site", "[breakpoint]") {
    auto proc = process::launch("test/targets/run_endlessly");
    const auto &cproc = proc;

    REQUIRE_THROWS_AS(proc->breakpoint_sites().get_by_address(virt_addr{42}), error);
    REQUIRE_THROWS_AS(proc->breakpoint_sites().get_by_id(44), error);
    REQUIRE_THROWS_AS(cproc->breakpoint_sites().get_by_address(virt_addr{42}), error);
    REQUIRE_THROWS_AS(cproc->breakpoint_sites().get_by_id(44), error);
}

TEST_CASE("Can iterate breakpoint sites", "[breakpoint]") {
    auto proc = process::launch("test/targets/run_endlessly");
    const auto &cproc = proc;

    proc->create_breakpoint_site(virt_addr{42});
    proc->create_breakpoint_site(virt_addr{43});
    proc->create_breakpoint_site(virt_addr{44});
    proc->create_breakpoint_site(virt_addr{45});

    // mutable allows us to increment addr inside the lambda
    proc->breakpoint_sites().for_each(
        [addr = 42](auto &site) mutable { REQUIRE(site.address().addr() == addr++); });

    cproc->breakpoint_sites().for_each(
        [addr = 42](auto &site) mutable { REQUIRE(site.address().addr() == addr++); });
}

TEST_CASE("Breakpoint on address works", "[breakpoint]") {
    bool close_on_exec = false;
    jaydb::pipe channel(close_on_exec);

    auto proc = process::launch("test/targets/hello_jaydb", true, channel.get_write());
    channel.close_write();

    auto offset = get_entry_point_offset("test/targets/hello_jaydb");
    auto load_address = get_load_address(proc->pid(), offset);

    proc->create_breakpoint_site(load_address).enable();
    proc->resume();
    auto reason = proc->wait_on_signal();

    REQUIRE(reason.reason == process_state::stopped);
    REQUIRE(reason.info == SIGTRAP);
    REQUIRE(proc->get_pc() == load_address);

    proc->resume();
    reason = proc->wait_on_signal();

    REQUIRE(reason.reason == process_state::exited);
    REQUIRE(reason.info == 0);

    auto data = channel.read();
    REQUIRE(to_string_view(data) == "Hello, jaydb!\n");
}

TEST_CASE("Can remove breakpoint sites", "[breakpoint]") {
    auto proc = process::launch("test/targets/run_endlessly");

    auto &site = proc->create_breakpoint_site(virt_addr{42});
    proc->create_breakpoint_site(virt_addr{43});
    REQUIRE(proc->breakpoint_sites().size() == 2);

    proc->breakpoint_sites().remove_by_id(site.id());
    proc->breakpoint_sites().remove_by_address(virt_addr{43});
    // std::cout << proc->breakpoint_sites().size();
    REQUIRE(proc->breakpoint_sites().empty());
}
