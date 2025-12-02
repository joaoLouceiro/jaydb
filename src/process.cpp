#include <cerrno>
#include <csignal>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <libjdb/bit.hpp>
#include <libjdb/breakpoint_site.hpp>
#include <libjdb/error.hpp>
#include <libjdb/pipe.hpp>
#include <libjdb/process.hpp>
#include <libjdb/register_info.hpp>
#include <libjdb/stoppoint_collection.hpp>
#include <libjdb/types.hpp>
#include <memory>
#include <optional>
#include <string>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

namespace {
void exit_with_perror(jdb::pipe &channel, std::string const &prefix) {
    auto message = prefix + ": " + std::strerror(errno);
    channel.write(reinterpret_cast<std::byte *>(message.data()), message.size());
    exit(-1);
}
} // namespace

jdb::breakpoint_site &jdb::process::create_breakpoint_site(jdb::virt_addr address) {
    if (breakpoint_sites_.contains_address(address)) {
        error::send("Breakpoint site already created at address " + std::to_string(address.addr()));
    }
    return breakpoint_sites_.push(
        std::unique_ptr<breakpoint_site>(new breakpoint_site(*this, address)));
}

std::unique_ptr<jdb::process> jdb::process::launch(std::filesystem::path path, bool debug,
                                                   std::optional<int> stdout_replacement) {
    pipe channel(true);
    pid_t pid;
    // fork is a syscall that splits the running process into two different processes
    if ((pid = fork()) < 0) {
        error::send_errno("fork failed");
    }
    if (pid == 0) {
        // Because the child process will not be reading from the pipe, we can close it immediately
        channel.close_read();
        if (stdout_replacement) {
            // dup2 copies the content of the first file descriptor to the second, and then closes
            // the latter. This means that stdout will be replaced with stdout_replacement, which
            // could be a file or a pipe
            if (dup2(*stdout_replacement, STDOUT_FILENO) < 0) {
                exit_with_perror(channel, "stdout_replacement failed");
            }
        }
        // fork returns 0 to the child process
        // Execute debugee
        if (debug && ptrace(PTRACE_TRACEME, 0, nullptr, nullptr)) {
            exit_with_perror(channel, "Tracing failed");
        }
        // exec* is a family of syscalls that replaces the currently executing program with a
        // new one. The l means that the arguments will be passed to the program individually,
        // as opposed to an array. The p tells exec to look for the given program name in the
        // PATH environment variable.
        if (execlp(path.c_str(), path.c_str(), nullptr) < 0) {
            exit_with_perror(channel, "exec failed");
        }
    }
    channel.close_write();
    auto data = channel.read();
    channel.close_read();
    // If any data has been written to the pipe, then an error has been thrown by the child.
    if (data.size() > 0) {
        waitpid(pid, nullptr, 0);
        auto chars = reinterpret_cast<char *>(data.data());
        error::send(std::string(chars, chars + data.size()));
    }
    std::unique_ptr<process> proc(
        new process(pid, /*terminate_on_end=*/true, /*is_attached=*/debug));
    if (debug) {
        proc->wait_on_signal();
    }
    return proc;
}

std::unique_ptr<jdb::process> jdb::process::attach(pid_t pid) {
    if (pid == 0) {
        error::send("Invalid PID");
    }
    if (ptrace(PTRACE_ATTACH, pid, nullptr, nullptr) < 0) {
        error::send_errno("Could not attach");
    }

    std::unique_ptr<process> proc(
        new process(pid, /*terminate_on_end=*/false, /*is_attached=*/true));
    proc->wait_on_signal();

    return proc;
}

jdb::process::~process() {
    if (pid_ != 0) {
        int status;
        if (is_attached_) {
            if (state_ == process_state::running) {
                kill(pid_, SIGSTOP);
                waitpid(pid_, &status, 0);
            }
            ptrace(PTRACE_DETACH, pid_, nullptr, nullptr);
            kill(pid_, SIGCONT);
        }

        if (terminate_on_end_) {
            kill(pid_, SIGKILL);
            waitpid(pid_, &status, 0);
        }
    }
}

// Wrapper for PTRACE_CONT
void jdb::process::resume() {
    if (ptrace(PTRACE_CONT, pid_, nullptr, nullptr) < 0) {
        error::send_errno("Could not resume");
    }
    state_ = process_state::running;
}

jdb::stop_reason::stop_reason(int wait_status) {
    if (WIFEXITED(wait_status)) {
        reason = process_state::exited;
        info = WEXITSTATUS(wait_status);
    } else if (WIFSIGNALED(wait_status)) {
        reason = process_state::terminated;
        info = WTERMSIG(wait_status);
    } else if (WIFSTOPPED(wait_status)) {
        reason = process_state::stopped;
        info = WSTOPSIG(wait_status);
    }
}

// Wrapper for waitpid
jdb::stop_reason jdb::process::wait_on_signal() {
    int wait_status;
    int options = 0;
    if (waitpid(pid_, &wait_status, options) < 0) {
        error::send_errno("waitpid failed");
    }
    stop_reason reason(wait_status);
    state_ = reason.reason;

    if (is_attached_ && state_ == process_state::stopped) {
        read_all_registers();
    }

    return reason;
}

void jdb::process::read_all_registers() {
    if (ptrace(PTRACE_GETREGS, pid_, nullptr, &get_registers().data_.regs) < 0) {
        error::send_errno("Could not read GPR registers");
    }
    if (ptrace(PTRACE_GETFPREGS, pid_, nullptr, &get_registers().data_.i387) < 0) {
        error::send_errno("Could not read FPR registers");
    }
    for (int i = 0; i < 8; ++i) {
        auto id = static_cast<int>(register_id::dr0) + i;
        auto info = register_info_by_id(static_cast<register_id>(id));

        errno = 0;
        std::int64_t data = ptrace(PTRACE_PEEKUSER, pid_, info.offset, nullptr);
        if (errno != 0) {
            error::send_errno("Could not read debug register");
        }

        get_registers().data_.u_debugreg[i] = data;
    }
}

void jdb::process::write_user_area(std::size_t offset, std::uint64_t data) {
    if (ptrace(PTRACE_POKEUSER, pid_, offset, data) < 0) {
        error::send_errno("Could not write to user area");
    }
}

void jdb::process::write_fprs(const user_fpregs_struct &fprs) {
    if (ptrace(PTRACE_SETFPREGS, pid_, nullptr, &fprs) < 0) {
        error::send_errno("Could not write floating point registers");
    }
}

void jdb::process::write_gprs(const user_regs_struct &gprs) {
    if (ptrace(PTRACE_SETREGS, pid_, nullptr, &gprs) < 0) {
        error::send_errno("Could not write general purpose registers");
    }
}
