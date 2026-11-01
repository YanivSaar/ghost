//! Launch-and-track: fork() a child, SIGSTOP it before execve, hand the
//! paused PID to the supervisor so it can be inserted into the eBPF PID_SET,
//! then SIGCONT and let the child execvp(). The small handshake lets ghost
//! observe the child from its very first syscall after execve returns.
//!
//! Returns a `CmdHandle` that owns the child PID and offers a `wait()` for
//! the reaper thread to collect the exit status.

use std::ffi::CString;

use anyhow::{bail, Context, Result};

pub struct CmdHandle {
    pub pid: libc::pid_t,
}

impl CmdHandle {
    /// Fork, stop in the child before execve, and return the stopped child's PID.
    /// Caller must call `resume()` after wiring PID_SET to let the child run.
    pub fn spawn_stopped(argv: &[String]) -> Result<Self> {
        if argv.is_empty() {
            bail!("ghost cold: command is empty");
        }

        // Build execvp argv (null-terminated).
        let c_argv: Vec<CString> = argv.iter()
            .map(|s| CString::new(s.as_str()).unwrap())
            .collect();
        let mut c_argv_ptrs: Vec<*const libc::c_char> =
            c_argv.iter().map(|s| s.as_ptr()).collect();
        c_argv_ptrs.push(std::ptr::null());

        // Fork.
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            return Err(std::io::Error::last_os_error()).context("fork");
        }

        if pid == 0 {
            // Child: stop ourselves, then (on resume) execvp.
            unsafe {
                libc::raise(libc::SIGSTOP);
                libc::execvp(c_argv_ptrs[0], c_argv_ptrs.as_ptr());
                // execvp returned → it failed.
                let errno = *libc::__errno_location();
                libc::write(2, b"ghost cold: execvp failed\n".as_ptr() as _, 25);
                libc::_exit(127 + (errno & 0x7f));
            }
        }

        // Parent: wait until child is stopped by its SIGSTOP.
        let mut status: libc::c_int = 0;
        let w = unsafe { libc::waitpid(pid, &mut status, libc::WUNTRACED) };
        if w < 0 {
            return Err(std::io::Error::last_os_error()).context("waitpid(WUNTRACED)");
        }
        if !libc::WIFSTOPPED(status) {
            bail!("ghost cold: child did not stop (status={status})");
        }

        Ok(Self { pid: pid as libc::pid_t })
    }

    /// Resume the stopped child; this is the "launch" instant.
    pub fn resume(&self) -> Result<()> {
        let r = unsafe { libc::kill(self.pid, libc::SIGCONT) };
        if r < 0 {
            return Err(std::io::Error::last_os_error()).context("kill(SIGCONT)");
        }
        Ok(())
    }

    /// Block until the child exits; returns its decoded status.
    pub fn wait(&self) -> Result<i32> {
        let mut status: libc::c_int = 0;
        let w = unsafe { libc::waitpid(self.pid, &mut status, 0) };
        if w < 0 {
            return Err(std::io::Error::last_os_error()).context("waitpid");
        }
        let code = if libc::WIFEXITED(status) {
            libc::WEXITSTATUS(status)
        } else if libc::WIFSIGNALED(status) {
            128 + libc::WTERMSIG(status)
        } else {
            status
        };
        Ok(code)
    }
}
