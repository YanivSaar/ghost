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
        let c_argv: Vec<CString> = argv
            .iter()
            .map(|s| CString::new(s.as_str()).unwrap())
            .collect();
        let mut c_argv_ptrs: Vec<*const libc::c_char> = c_argv.iter().map(|s| s.as_ptr()).collect();
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
                let msg = b"ghost cold: execvp failed\n";
                libc::write(2, msg.as_ptr() as _, msg.len());
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

        Ok(Self {
            pid: pid as libc::pid_t,
        })
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_argv_errors() {
        let r = CmdHandle::spawn_stopped(&[]);
        assert!(r.is_err(), "empty argv must error");
    }

    #[test]
    #[should_panic]
    fn argv_with_nul_byte_panics_on_cstring() {
        // CString::new rejects interior NULs; the current code does an
        // `.unwrap()` which panics. Locking down current behaviour so a
        // change to graceful handling is visible in the diff.
        let argv = vec!["bad\0arg".to_string()];
        let _ = CmdHandle::spawn_stopped(&argv);
    }

    #[test]
    fn spawn_and_wait_true_exits_zero() {
        // /bin/true exists on every POSIX system; it exits with 0.
        if !std::path::Path::new("/bin/true").exists() {
            // Non-POSIX test env — skip rather than fail.
            return;
        }
        let h = CmdHandle::spawn_stopped(&["/bin/true".to_string()]).expect("spawn /bin/true");
        h.resume().expect("resume");
        let code = h.wait().expect("wait");
        assert_eq!(code, 0, "/bin/true should exit 0");
    }

    #[test]
    fn spawn_nonexistent_exe_exits_nonzero() {
        // The fork + SIGSTOP handshake succeeds; execvp fails inside the
        // child and the child's _exit(127 + errno) returns nonzero via wait.
        let h = CmdHandle::spawn_stopped(&["/no/such/binary/for/ghost/test".to_string()])
            .expect("spawn (fork+stop) still succeeds");
        h.resume().expect("resume");
        let code = h.wait().expect("wait");
        assert_ne!(
            code, 0,
            "execvp of a missing binary must yield nonzero exit"
        );
    }
}
