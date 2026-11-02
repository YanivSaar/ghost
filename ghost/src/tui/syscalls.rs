//! Shared x86_64 syscall-number → name map used by every lens screen.
//!
//! Previously each screen (overview / catch / cold) carried its own copy
//! with a different, overlapping subset of entries, so the same event
//! would render under one name on one screen and `?` on another.

pub fn syscall_name(nr: u32) -> &'static str {
    match nr {
        0 => "read",
        1 => "write",
        2 => "open",
        3 => "close",
        4 => "stat",
        5 => "fstat",
        6 => "lstat",
        7 => "poll",
        8 => "lseek",
        9 => "mmap",
        10 => "mprotect",
        11 => "munmap",
        12 => "brk",
        13 => "rt_sigaction",
        14 => "rt_sigprocmask",
        17 => "pread64",
        18 => "pwrite64",
        19 => "readv",
        20 => "writev",
        21 => "access",
        23 => "select",
        24 => "sched_yield",
        28 => "madvise",
        32 => "dup",
        33 => "dup2",
        35 => "nanosleep",
        38 => "setitimer",
        39 => "getpid",
        41 => "socket",
        42 => "connect",
        43 => "accept",
        44 => "sendto",
        45 => "recvfrom",
        46 => "sendmsg",
        47 => "recvmsg",
        48 => "shutdown",
        49 => "bind",
        50 => "listen",
        51 => "getsockname",
        52 => "getpeername",
        54 => "setsockopt",
        55 => "getsockopt",
        56 => "clone",
        57 => "fork",
        59 => "execve",
        60 => "exit",
        61 => "wait4",
        62 => "kill",
        63 => "uname",
        72 => "fcntl",
        73 => "flock",
        74 => "fsync",
        78 => "getdents",
        79 => "getcwd",
        80 => "chdir",
        82 => "rename",
        83 => "mkdir",
        87 => "unlink",
        89 => "readlink",
        96 => "gettimeofday",
        97 => "getrlimit",
        102 => "getuid",
        104 => "getgid",
        105 => "setuid",
        106 => "setgid",
        107 => "geteuid",
        108 => "getegid",
        110 => "getppid",
        111 => "getpgrp",
        158 => "arch_prctl",
        186 => "gettid",
        202 => "futex",
        218 => "set_tid_address",
        228 => "clock_gettime",
        230 => "clock_nanosleep",
        231 => "exit_group",
        232 => "epoll_wait",
        233 => "epoll_ctl",
        234 => "tgkill",
        249 => "fallocate",
        257 => "openat",
        262 => "newfstatat",
        267 => "readlinkat",
        269 => "faccessat",
        270 => "pselect6",
        271 => "ppoll",
        273 => "set_robust_list",
        281 => "epoll_pwait",
        290 => "accept4",
        291 => "signalfd4",
        292 => "eventfd2",
        293 => "epoll_create1",
        302 => "prlimit64",
        316 => "renameat2",
        318 => "getrandom",
        334 => "rseq",
        _ => "?",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn covers_entries_from_all_screens() {
        // Union across the old per-screen tables.
        assert_eq!(syscall_name(0), "read");
        assert_eq!(syscall_name(4), "stat"); // was ? in catch
        assert_eq!(syscall_name(18), "pwrite64"); // was ? in cold
        assert_eq!(syscall_name(158), "arch_prctl"); // was ? in overview+catch
        assert_eq!(syscall_name(273), "set_robust_list"); // was ? in overview+catch
    }

    #[test]
    fn unknown_renders_as_question_mark() {
        assert_eq!(syscall_name(9999), "?");
    }
}
