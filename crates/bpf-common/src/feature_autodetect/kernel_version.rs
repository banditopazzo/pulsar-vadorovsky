//! Extract kernel version from the currently running system.
//! Code ported from libbpf.

use anyhow::{Context, Result};
use nix::fcntl::AtFlags;
use nix::sys::utsname::uname;
use nix::unistd::{faccessat, AccessFlags};

#[derive(Debug, Clone, PartialEq)]
pub struct KernelVersion {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
}

impl KernelVersion {
    pub fn autodetect() -> Result<KernelVersion> {
        // On Ubuntu LINUX_VERSION_CODE doesn't correspond to info.release,
        // but Ubuntu provides /proc/version_signature file, as described at
        // https://ubuntu.com/kernel, with an example contents below, which we
        // can use to get a proper LINUX_VERSION_CODE.
        //
        //   Ubuntu 5.4.0-12.15-generic 5.4.8
        //
        // In the above, 5.4.8 is what kernel is actually expecting, while
        // uname() call will return 5.4.0 in info.release.
        if faccessat(
            None,
            "/proc/version_signature",
            AccessFlags::R_OK,
            // TODO: switch to AT_EACCESS once this patch is merged and released:
            // https://github.com/nix-rust/nix/pull/1995
            // As a workaround we're using AT_REMOVEDIR, which has the same value on linux
            AtFlags::AT_REMOVEDIR,
        )
        .is_ok()
        {
            if let Ok(value) = std::fs::read_to_string("/proc/version_signature") {
                return Self::parse_version_signature(&value);
            }
        }
        Self::parse_uname_release(
            uname()
                .context("Getting kernel version calling uname() failed")?
                .release()
                .to_str()
                .context("Kernel version from uname contained invalid characters")?,
        )
    }

    /// Parse release fields from the format "%*s %*s %d.%d.%d\n"
    fn parse_version_signature(value: &str) -> Result<KernelVersion> {
        let parse = |value: &str| -> Option<KernelVersion> {
            let version_items: Vec<&str> = value
                .split_whitespace()
                .skip(2)
                .next()?
                .split('.')
                .collect();
            if let [major, minor, patch] = version_items[..] {
                Some(KernelVersion {
                    major: major.parse().ok()?,
                    minor: minor.parse().ok()?,
                    patch: patch.parse().ok()?,
                })
            } else {
                None
            }
        };
        parse(value).with_context(|| format!("Invalid version_signature format: {value}"))
    }

    /// Parse release fields from the format "%d.%d.%d"
    fn parse_uname_release(value: &str) -> Result<KernelVersion> {
        let parse = |value: &str| -> Option<KernelVersion> {
            let version_items: Vec<&str> = value.split('.').collect();
            if let [major, minor, patch] = version_items[..] {
                Some(KernelVersion {
                    major: major.parse().ok()?,
                    minor: minor.parse().ok()?,
                    patch: patch.parse().ok()?,
                })
            } else {
                None
            }
        };
        parse(value).with_context(|| format!("Invalid version_signature format: {value}"))
    }

    /// Encode to a single i32 as the kernel macro KERNEL_VERSION()
    pub fn as_i32(&self) -> i32 {
        ((self.major << 16) + (self.minor << 8) + self.patch.max(255)) as i32
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_version_signature() {
        assert_eq!(
            KernelVersion::parse_version_signature("Ubuntu 5.4.0-12.15-generic 5.4.8\n").unwrap(),
            KernelVersion {
                major: 5,
                minor: 4,
                patch: 8
            }
        );
    }

    #[test]
    fn parse_uname_release() {
        assert_eq!(
            KernelVersion::parse_uname_release("5.17.4").unwrap(),
            KernelVersion {
                major: 5,
                minor: 17,
                patch: 4
            }
        );
    }

    #[test]
    fn int_conversion() {
        assert_eq!(
            KernelVersion {
                major: 5,
                minor: 17,
                patch: 4
            }
            .as_i32(),
            332287
        );
    }
}
