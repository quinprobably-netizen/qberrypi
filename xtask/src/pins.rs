//! The packages `cargo xtask fetch` downloads, each pinned by a digest, and
//! the files taken from them.
//!
//! Changing a kernel pin means changing the kernel release in every member
//! path below as well.

/// The digest a downloaded package must have, as lowercase hexadecimal.
pub enum Digest {
    /// A SHA-256 digest.
    Sha256(&'static str),
    /// A SHA-512 digest.
    Sha512(&'static str),
}

/// One pinned Debian package and the files wanted from it.
pub struct Package {
    /// A short name for progress messages.
    pub name: &'static str,
    /// Where the package is downloaded from.
    pub url: &'static str,
    /// The name the package is kept under in `vendor-cache/debs/`.
    pub file: &'static str,
    /// What the downloaded file must hash to.
    pub digest: Digest,
    /// Each wanted file: its path inside the package, then its path under `vendor-cache/extracted/`.
    pub wanted: &'static [(&'static str, &'static str)],
}

/// Every package the image takes files from.
pub const PACKAGES: &[Package] = &[
    Package {
        name: "kernel",
        url: "https://archive.raspberrypi.com/debian/pool/main/l/linux/linux-image-6.18.60%2brpt-rpi-v8_6.18.60-1%2brpt1_arm64.deb",
        file: "linux-image-6.18.60+rpt-rpi-v8_6.18.60-1+rpt1_arm64.deb",
        digest: Digest::Sha512(
            "4d1ade18ab30899d6733f23fb41c1705a79bb3a56186bbde38e7a10ab53b168e338de8b39f5a28f2f4ebd1099a97eaafd07bf35a60d98dd45922e873e20e5633",
        ),
        wanted: &[
            ("boot/vmlinuz-6.18.60+rpt-rpi-v8", "kernel8.img"),
            (
                "usr/lib/modules/6.18.60+rpt-rpi-v8/dtb/broadcom/bcm2710-rpi-3-b-plus.dtb",
                "bcm2710-rpi-3-b-plus.dtb",
            ),
            (
                "usr/lib/modules/6.18.60+rpt-rpi-v8/kernel/net/rfkill/rfkill.ko.xz",
                "modules/rfkill.ko",
            ),
            (
                "usr/lib/modules/6.18.60+rpt-rpi-v8/kernel/net/wireless/cfg80211.ko.xz",
                "modules/cfg80211.ko",
            ),
            (
                "usr/lib/modules/6.18.60+rpt-rpi-v8/kernel/drivers/net/wireless/broadcom/brcm80211/brcmutil/brcmutil.ko.xz",
                "modules/brcmutil.ko",
            ),
            (
                "usr/lib/modules/6.18.60+rpt-rpi-v8/kernel/drivers/net/wireless/broadcom/brcm80211/brcmfmac/brcmfmac.ko.xz",
                "modules/brcmfmac.ko",
            ),
            (
                "usr/lib/modules/6.18.60+rpt-rpi-v8/kernel/drivers/net/wireless/broadcom/brcm80211/brcmfmac/cyw/brcmfmac-cyw.ko.xz",
                "modules/brcmfmac-cyw.ko",
            ),
        ],
    },
    Package {
        name: "Wi-Fi firmware",
        url: "https://archive.raspberrypi.com/debian/pool/main/f/firmware-nonfree/firmware-brcm80211_20260519-1%7ebpo13%2b1%2brpt1_all.deb",
        file: "firmware-brcm80211_20260519-1~bpo13+1+rpt1_all.deb",
        digest: Digest::Sha512(
            "1b10228d2518ca5628e428796ed1aac924f20fc3faddf38b177c047bff3d79ccd6f370bbccd6e80347b798584e752f5b03554ab3d56b16591fcb4ee4247acc1e",
        ),
        wanted: &[
            (
                "usr/lib/firmware/cypress/cyfmac43455-sdio-standard.bin",
                "firmware/brcm/brcmfmac43455-sdio.bin",
            ),
            (
                "usr/lib/firmware/cypress/cyfmac43455-sdio.clm_blob",
                "firmware/brcm/brcmfmac43455-sdio.clm_blob",
            ),
            (
                "usr/lib/firmware/brcm/brcmfmac43455-sdio.txt",
                "firmware/brcm/brcmfmac43455-sdio.txt",
            ),
        ],
    },
    Package {
        name: "regulatory db",
        url: "https://deb.debian.org/debian/pool/main/w/wireless-regdb/wireless-regdb_2026.05.30-1%7edeb13u1_all.deb",
        file: "wireless-regdb_2026.05.30-1~deb13u1_all.deb",
        digest: Digest::Sha256("72048ee2f369a8c2df8b5f99f79489d3812d869282038cfe55e23a4748231399"),
        wanted: &[
            (
                "usr/lib/firmware/regulatory.db-upstream",
                "firmware/regulatory.db",
            ),
            (
                "usr/lib/firmware/regulatory.db.p7s-upstream",
                "firmware/regulatory.db.p7s",
            ),
        ],
    },
];

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::path::{Component, Path};

    #[test]
    fn the_packages_produce_the_twelve_files_the_image_needs() {
        let mut outputs: Vec<&str> = PACKAGES
            .iter()
            .flat_map(|package| package.wanted.iter().map(|(_, output)| *output))
            .collect();
        outputs.sort_unstable();

        assert_eq!(
            outputs,
            [
                "bcm2710-rpi-3-b-plus.dtb",
                "firmware/brcm/brcmfmac43455-sdio.bin",
                "firmware/brcm/brcmfmac43455-sdio.clm_blob",
                "firmware/brcm/brcmfmac43455-sdio.txt",
                "firmware/regulatory.db",
                "firmware/regulatory.db.p7s",
                "kernel8.img",
                "modules/brcmfmac-cyw.ko",
                "modules/brcmfmac.ko",
                "modules/brcmutil.ko",
                "modules/cfg80211.ko",
                "modules/rfkill.ko",
            ]
        );
    }

    #[test]
    fn every_name_the_table_writes_to_stays_inside_its_folder() {
        for package in PACKAGES {
            assert!(!package.file.contains('/'), "{}", package.file);
            assert!(package.file.ends_with(".deb"), "{}", package.file);
            for (_, output) in package.wanted {
                let plain = Path::new(output)
                    .components()
                    .all(|part| matches!(part, Component::Normal(_)));
                assert!(plain, "{output}");
            }
        }
    }

    #[test]
    fn every_package_is_fetched_over_https_under_its_own_file_name() {
        let files: HashSet<&str> = PACKAGES.iter().map(|package| package.file).collect();
        assert_eq!(files.len(), PACKAGES.len());
        for package in PACKAGES {
            assert!(package.url.starts_with("https://"), "{}", package.url);
        }
    }
}
