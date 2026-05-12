#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <editline/readline.h>
#include <fmt/base.h>
#include <fmt/format.h>
#include <fmt/ranges.h>
#include <iostream>
#include <libjaydb/breakpoint_site.hpp>
#include <libjaydb/error.hpp>
#include <libjaydb/parse.hpp>
#include <libjaydb/process.hpp>
#include <libjaydb/register_info.hpp>
#include <libjaydb/registers.hpp>
#include <libjaydb/types.hpp>
#include <memory>
#include <sstream>
#include <string>
#include <string_view>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <type_traits>
#include <unistd.h>
#include <variant>
#include <vector>

namespace {
bool is_prefix(std::string_view str, std::string_view of) {
    if (str.size() > of.size())
        return false;
    return std::equal(str.begin(), str.end(), of.begin());
}

void print_help(const std::vector<std::string> &args) {
    if (args.size() == 1) {
        std::cerr << R"(Available commands:
breakpoint  - Commands for operating on breakpoints
continue    - Resume the process
register    - Commands for operating on register
step        - Step over a single instruction
)";
    } else if (is_prefix(args[1], "register")) {
        std::cerr << R"(Available commands:
read
read <register>
read all
write <register> <value>
)";
    } else if (is_prefix(args[1], "breakpoint")) {
        std::cerr << R"(Available commands:
list
delete <id>
disable <id>
enable <id>
set <address>
)";
    } else {
        std::cerr << "No help available on that\n";
    }
}

void handle_breakpoint_command(jaydb::process &process, const std::vector<std::string> &args) {
    if (args.size() < 2) {
        print_help({"help", "breakpoint"});
        return;
    }

    if (is_prefix(args[1], "list")) {
        if (process.breakpoint_sites().empty()) {
            fmt::print("No breakpoints set\n");
        } else {
            fmt::print("Current breakpoints:\n");
            process.breakpoint_sites().for_each([](auto &site) {
                fmt::print("{}: address = {:#x}, {}\n", site.id(), site.address().addr(),
                           site.is_enabled() ? "enabled" : "disabled");
            });
        }
        return;
    }

    // Add method for setting a breakpoint,
    // command = 'set'
    // args[2] = address. Make use of jaydb::parse::to_integral

    if (args.size() < 3) {
        print_help({"help", "breakpoint"});
        return;
    }

    if (is_prefix(args[1], "set")) {
        auto address = jaydb::to_integral<uint64_t>(args[2], 16);
        if (!address) {
            fmt::print(stderr, "Breakpoint command expects address in"
                               "hexadecimal, prefixed with '0x'\n");
            return;
        }

        process.create_breakpoint_site(jaydb::virt_addr{*address}).enable();
        return;
    }

    // Create methods for enabling, disabling and deleting a breakpoint_site, based on ID.
    auto id = jaydb::to_integral<jaydb::breakpoint_site::id_type>(args[2]);
    if (!id) {
        std::cerr << "Command expects breakpoint ID\n";
        return;
    }

    if (is_prefix(args[2], "enable")) {
        process.breakpoint_sites().get_by_id(*id).enable();
    } else if (is_prefix(args[2], "disable")) {
        process.breakpoint_sites().get_by_id(*id).disable();
    } else if (is_prefix(args[2], "remove")) {
        process.breakpoint_sites().remove_by_id(*id);
    }
}

void handle_register_read(jaydb::process &process, const std::vector<std::string> &args) {
    auto format = [](auto t) {
        /*
         * If the register is of type double, return the value of it as is
         * Else, if it is of any integral type (char, int, long, short), pad the string with two
         * 0's for every byte, plus two chars for the leading 0x. If the register is a vector,
         * format the string as [0xtt, 0xtt...] (04 makes it 4 chars wide).
         */
        if constexpr (std::is_floating_point_v<decltype(t)>) {
            // return value to lambda function
            return fmt::format("{}", t);
        } else if constexpr (std::is_integral_v<decltype(t)>) {
            return fmt::format("{:#0{}x}", t, sizeof(t) * 2 + 2);
        } else {
            return fmt::format("[{:#04x}]", fmt::join(t, ","));
        }
    };

    if (args.size() == 2 || (args.size() == 3 && args[2] == "all")) {
        for (auto &info : jaydb::g_register_infos) {
            auto should_print = (args.size() == 3 || info.type == jaydb::register_type::gpr) &&
                                info.name != "orig_rax";
            if (!should_print)
                continue;
            auto value = process.get_registers().read(info);
            fmt::print("{}:\t{}\n", info.name, std::visit(format, value));
        }
    } else if (args.size() == 3) {
        try {
            auto info = jaydb::register_info_by_name(args[2]);
            auto value = process.get_registers().read(info);
            fmt::print("{}:\t{}\n", info.name, std::visit(format, value));
        } catch (jaydb::error &err) {
            std::cerr << "No such register\n";
            return;
        }
    } else {
        print_help({"help", "register"});
    }
}
jaydb::registers::value parse_register_value(jaydb::register_info info, std::string_view text) {
    try {
        if (info.format == jaydb::register_format::uint) {
            switch (info.size) {
            case 1:
                return jaydb::to_integral<std::uint8_t>(text, 16).value();
            case 2:
                return jaydb::to_integral<std::uint16_t>(text, 16).value();
            case 4:
                return jaydb::to_integral<std::uint32_t>(text, 16).value();
            case 8:
                return jaydb::to_integral<std::uint64_t>(text, 16).value();
            }
        } else if (info.format == jaydb::register_format::double_float) {
            return jaydb::to_float<double>(text).value();

        } else if (info.format == jaydb::register_format::long_double) {
            return jaydb::to_float<long double>(text).value();
        } else if (info.format == jaydb::register_format::vector) {
            if (info.size == 8) {
                return jaydb::parse_vector<8>(text);
            } else if (info.size == 16) {
                return jaydb::parse_vector<16>(text);
            }
        }
    } catch (...) {
    }
    jaydb::error::send("Invalid format");
}

void handle_register_write(jaydb::process &process, const std::vector<std::string> &args) {
    if (args.size() != 4) {
        print_help({"help", "register"});
        return;
    }
    try {
        auto info = jaydb::register_info_by_name(args[2]);
        auto value = parse_register_value(info, args[3]);
        process.get_registers().write(info, value);
    } catch (jaydb::error &err) {
        std::cerr << err.what() << '\n';
        return;
    }
}

void handle_register_command(jaydb::process &process, const std::vector<std::string> &args) {
    if (args.size() < 2) {
        print_help({"help", "register"});
        return;
    }
    if (is_prefix(args[1], "read")) {
        handle_register_read(process, args);
    } else if (is_prefix(args[1], "write")) {
        handle_register_write(process, args);
    } else {
        print_help({"help", "register"});
    }
}

std::unique_ptr<jaydb::process> attach(int argc, const char **argv) {
    pid_t pid = 0;
    // Passing a PID
    if (argc == 3 && argv[1] == std::string_view("-p")) {
        // In this branch, the program will attach to a running process
        pid = std::atoi(argv[2]);
        return jaydb::process::attach(pid);
    } else {
        const char *program_path = argv[1];
        auto proc = jaydb::process::launch(program_path);
        fmt::print("Launched process with PID {}\n", proc->pid());
        return proc;
    }
}

std::vector<std::string> split(std::string_view str, char delimiter) {
    std::vector<std::string> out{};
    std::stringstream ss{std::string{str}};
    std::string item;
    while (std::getline(ss, item, delimiter)) {
        out.push_back(item);
    }
    return out;
}

void print_stop_reason(const jaydb::process &process, jaydb::stop_reason reason) {
    std::string message;
    switch (reason.reason) {
    case jaydb::process_state::exited:
        message = fmt::format("exited with status {}", static_cast<int>(reason.info));
        break;
    case jaydb::process_state::terminated:
        message = fmt::format("terminated with signal {}", sigabbrev_np(reason.info));
        break;
    case jaydb::process_state::stopped:
        message = fmt::format("stopped with signal {} at {:#x}", sigabbrev_np(reason.info),
                              process.get_pc().addr());
        break;
    }
    fmt::print("Process {} {}\n", process.pid(), message);
}

void handle_command(std::unique_ptr<jaydb::process> &process, std::string_view line) {
    auto args = split(line, ' ');
    auto command = args[0];
    if (is_prefix(command, "continue")) {
        process->resume();
        auto reason = process->wait_on_signal();
        print_stop_reason(*process, reason);
    } else if (is_prefix(command, "register")) {
        handle_register_command(*process, args);
    } else if (is_prefix(command, "help")) {
        print_help(args);
    } else if (is_prefix(command, "breakpoint")) {
        handle_breakpoint_command(*process, args);
    } else if (is_prefix(command, "step")) {
        auto reason = process->step_instruction();
        print_stop_reason(*process, reason);
    } else {
        std::cerr << "Unknown command\n";
    }
}

} // namespace

void main_loop(std::unique_ptr<jaydb::process> &process) {
    char *line = nullptr;
    // readline creates a prompt and returns a char* with whatever the user wrote.
    // If it reads an EOF, it returns nullptr
    while ((line = readline("jaydb> ")) != nullptr) {
        std::string line_str;

        // If the user doesn't write anything in the readline prompt, read the last command from the
        // libedit's history_list
        if (line == std::string_view("")) {
            // Freeing line's memory as soon as we figure out that we will not be using it, instead
            // of waiting for longer and risk missing it
            free(line);
            if (history_length > 0) {
                line_str = history_list()[history_length - 1]->line;
            }
        } else {
            line_str = line;
            add_history(line);
            free(line);
        }

        if (!line_str.empty()) {
            handle_command(process, line_str);
        }
    }
}

int main(int argc, const char **argv) {
    if (argc == 1) {
        std::cerr << "No arguments given\n";
        return -1;
    }
    try {
        auto process = attach(argc, argv);
        main_loop(process);
    } catch (const jaydb::error &err) {
        std::cout << err.what() << '\n';
    }
}
