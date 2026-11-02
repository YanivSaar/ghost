//! CAP_BPF / CAP_PERFMON / CAP_SYS_ADMIN probe for actionable error
//! messages.
//!
//! When `GhostEbpf::load()` fails on a vanilla user account, aya
//! surfaces a kernel errno (`EACCES` / `EPERM`) with no hint about
//! which capabilities are missing or how to grant them. This module
//! reads `/proc/self/status` and classifies the environment so the
//! caller can print a copy-pasteable fix for the host shape the user
//! is on.
//!
//! The relevant capability bits (from `include/uapi/linux/capability.h`):
//!
//!   CAP_SYS_ADMIN  = 21    (fallback: grants everything)
//!   CAP_PERFMON    = 38    (performance events, 5.8+)
//!   CAP_BPF        = 39    (BPF syscall, 5.8+)
//!
//! On kernels < 5.8 only CAP_SYS_ADMIN works. We expose both the raw
//! bits + a human-readable summary.

pub const CAP_SYS_ADMIN: u8 = 21;
pub const CAP_PERFMON: u8 = 38;
pub const CAP_BPF: u8 = 39;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CapCheck {
    pub cap_eff: u64,
    pub has_sys_admin: bool,
    pub has_perfmon: bool,
    pub has_bpf: bool,
}

impl CapCheck {
    pub fn is_sufficient_for_ebpf(&self) -> bool {
        // Either (CAP_BPF + CAP_PERFMON) OR CAP_SYS_ADMIN.
        (self.has_bpf && self.has_perfmon) || self.has_sys_admin
    }
}

/// Read the effective capability bitmap of the current process.
/// Returns `CapCheck { cap_eff: 0, .. }` if `/proc/self/status` can't
/// be read (should never happen on Linux, but the function stays
/// infallible so callers can use it inside an error-formatting path).
pub fn cap_probe() -> CapCheck {
    let text = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    probe_from_status(&text)
}

fn probe_from_status(status: &str) -> CapCheck {
    let cap_eff = parse_cap_eff(status).unwrap_or(0);
    CapCheck {
        cap_eff,
        has_sys_admin: bit_set(cap_eff, CAP_SYS_ADMIN),
        has_perfmon: bit_set(cap_eff, CAP_PERFMON),
        has_bpf: bit_set(cap_eff, CAP_BPF),
    }
}

fn parse_cap_eff(status: &str) -> Option<u64> {
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("CapEff:") {
            let hex = rest.trim();
            return u64::from_str_radix(hex, 16).ok();
        }
    }
    None
}

fn bit_set(mask: u64, bit: u8) -> bool {
    mask & (1u64 << bit) != 0
}

/// Shape of the host ghost is running on, as a hint for the remediation
/// text. Detected from `/proc/1/comm`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostShape {
    SystemdBareMetal,
    Container,
    Unknown,
}

pub fn host_shape() -> HostShape {
    let pid1 = std::fs::read_to_string("/proc/1/comm")
        .unwrap_or_default()
        .trim()
        .to_string();
    match pid1.as_str() {
        "systemd" => HostShape::SystemdBareMetal,
        "" => HostShape::Unknown,
        // Common container inits.
        "init" | "sh" | "bash" | "tini" | "catatonit" | "dumb-init" | "s6-svscan" | "runit" => {
            HostShape::Container
        }
        _ => HostShape::Unknown,
    }
}

/// A multi-line remediation hint keyed to the current host + capability
/// state. Call this when `GhostEbpf::load()` returns an error, append
/// to the error context.
pub fn remediation_hint() -> String {
    let caps = cap_probe();
    let shape = host_shape();
    let mut out = String::new();
    out.push_str(&format!(
        "ghost: eBPF load failed — effective caps = 0x{:016x}, missing: ",
        caps.cap_eff
    ));
    let mut missing = Vec::new();
    if !caps.has_bpf {
        missing.push("CAP_BPF");
    }
    if !caps.has_perfmon {
        missing.push("CAP_PERFMON");
    }
    if !caps.has_sys_admin && missing.len() == 2 {
        missing.push("(or CAP_SYS_ADMIN)");
    }
    if missing.is_empty() {
        out.push_str("none (caps look sufficient — see kernel version + lockdown)\n");
    } else {
        out.push_str(&missing.join(" + "));
        out.push('\n');
    }

    match shape {
        HostShape::SystemdBareMetal => {
            out.push_str(
                "  Fix: run as root, OR grant file caps on the ghost binary:\n\
                 \n\
                 \tsudo setcap cap_bpf,cap_perfmon=eip \"$(which ghost)\"\n\
                 \n\
                 If that fails on an older kernel (<5.8), fall back to cap_sys_admin:\n\
                 \n\
                 \tsudo setcap cap_sys_admin=eip \"$(which ghost)\"\n",
            );
        }
        HostShape::Container => {
            out.push_str(
                "  Fix: launch the container with eBPF capabilities granted.\n\
                 \n\
                 \tdocker run --cap-add=BPF --cap-add=PERFMON  ...\n\
                 \tpodman run --cap-add=BPF --cap-add=PERFMON  ...\n\
                 \n\
                 In Kubernetes:\n\
                 \n\
                 \tsecurityContext:\n\
                 \t  capabilities:\n\
                 \t    add: [\"BPF\", \"PERFMON\"]\n\
                 \n\
                 Rootless Podman also needs the newuidmap/newgidmap setuid \
                 helpers (uidmap package) and a kernel ≥ 5.8.\n",
            );
        }
        HostShape::Unknown => {
            out.push_str(
                "  Fix: run as root, OR grant file caps on the ghost binary:\n\
                 \n\
                 \tsudo setcap cap_bpf,cap_perfmon=eip \"$(which ghost)\"\n\
                 \n\
                 If this is a container, add --cap-add=BPF --cap-add=PERFMON \
                 to your runtime.\n",
            );
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_cap_eff_from_minimal_status() {
        let s = "Name:\tghost\n\
                 Uid:\t0 0 0 0\n\
                 CapEff:\t000001ffffffffff\n\
                 ThreadsMax:\t1\n";
        let probe = probe_from_status(s);
        // 0x1ffffffffff = bits 0..=40 set; includes CAP_BPF (39), CAP_PERFMON (38), CAP_SYS_ADMIN (21).
        assert!(probe.has_sys_admin);
        assert!(probe.has_perfmon);
        assert!(probe.has_bpf);
        assert!(probe.is_sufficient_for_ebpf());
    }

    #[test]
    fn parse_cap_eff_missing_bpf_bit() {
        // Caps mask has CAP_SYS_ADMIN only (bit 21 = 0x200000).
        let s = "CapEff:\t0000000000200000\n";
        let probe = probe_from_status(s);
        assert!(probe.has_sys_admin);
        assert!(!probe.has_bpf);
        assert!(!probe.has_perfmon);
        // sys_admin alone is sufficient.
        assert!(probe.is_sufficient_for_ebpf());
    }

    #[test]
    fn parse_cap_eff_zero_mask() {
        let s = "CapEff:\t0000000000000000\n";
        let probe = probe_from_status(s);
        assert!(!probe.has_sys_admin);
        assert!(!probe.has_bpf);
        assert!(!probe.has_perfmon);
        assert!(!probe.is_sufficient_for_ebpf());
    }

    #[test]
    fn parse_cap_eff_bpf_perfmon_only() {
        // bits 38 + 39: 0x80_0000_0000 | 0x40_0000_0000 = 0xc0_0000_0000.
        let s = "CapEff:\t000000c000000000\n";
        let probe = probe_from_status(s);
        assert!(!probe.has_sys_admin);
        assert!(probe.has_bpf);
        assert!(probe.has_perfmon);
        assert!(probe.is_sufficient_for_ebpf());
    }

    #[test]
    fn parse_cap_eff_rejects_malformed_hex() {
        let s = "CapEff:\tNOT_A_HEX_VALUE\n";
        let probe = probe_from_status(s);
        // Falls back to 0.
        assert_eq!(probe.cap_eff, 0);
    }

    #[test]
    fn parse_cap_eff_ignores_missing_line() {
        let s = "Name:\tghost\nUid:\t0 0 0 0\n";
        let probe = probe_from_status(s);
        assert_eq!(probe.cap_eff, 0);
    }

    #[test]
    fn remediation_hint_mentions_setcap_for_systemd_or_unknown() {
        // Can't force the shape here without mocking /proc/1/comm; just
        // verify the hint is non-empty and includes at least one fix.
        let hint = remediation_hint();
        assert!(!hint.is_empty());
        let has_setcap = hint.contains("setcap");
        let has_cap_add = hint.contains("cap-add");
        assert!(
            has_setcap || has_cap_add,
            "hint must contain actionable fix: {hint}"
        );
    }

    #[test]
    fn cap_probe_runs_on_real_proc_self_status() {
        // Smoke test: on a Linux cargo test host, /proc/self/status is
        // always readable, so cap_eff must be non-zero when running
        // under cargo test (at least some caps are inherited).
        let probe = cap_probe();
        // Just assert the function doesn't panic; whether we have caps
        // depends on who runs the test, so don't assert on bits.
        let _ = probe.cap_eff;
    }
}
