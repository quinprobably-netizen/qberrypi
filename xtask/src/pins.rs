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
            (
                "usr/lib/modules/6.18.60+rpt-rpi-v8/kernel/drivers/video/backlight/backlight.ko.xz",
                "modules/backlight.ko",
            ),
            (
                "usr/lib/modules/6.18.60+rpt-rpi-v8/kernel/drivers/staging/fbtft/fbtft.ko.xz",
                "modules/fbtft.ko",
            ),
            (
                "usr/lib/modules/6.18.60+rpt-rpi-v8/kernel/drivers/staging/fbtft/fb_ili9486.ko.xz",
                "modules/fb_ili9486.ko",
            ),
            (
                "usr/lib/modules/6.18.60+rpt-rpi-v8/kernel/drivers/spi/spi-bcm2835.ko.xz",
                "modules/spi-bcm2835.ko",
            ),
            (
                "usr/lib/modules/6.18.60+rpt-rpi-v8/kernel/drivers/input/touchscreen/ads7846.ko.xz",
                "modules/ads7846.ko",
            ),
            // qberrypi's own overlays: the firmware reads `ov-README` and then
            // `ov-overlay_map.dtb` and `ov-<overlay>.dtbo` from beside the kernel. The second
            // overlay, `disable-bt`, disables the Bluetooth device-tree node.
            (
                "usr/lib/modules/6.18.60+rpt-rpi-v8/dtb/overlays/README",
                "ov-README",
            ),
            (
                "usr/lib/modules/6.18.60+rpt-rpi-v8/dtb/overlays/overlay_map.dtb",
                "ov-overlay_map.dtb",
            ),
            (
                "usr/lib/modules/6.18.60+rpt-rpi-v8/dtb/overlays/piscreen.dtbo",
                "ov-qb-piscreen.dtbo",
            ),
            (
                "usr/lib/modules/6.18.60+rpt-rpi-v8/dtb/overlays/disable-bt.dtbo",
                "ov-disable-bt.dtbo",
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
    // The Raspberry Pi 3's boot firmware, which the card needs beside the slots (`cargo xtask
    // image`). It is not the Wi-Fi firmware above, which is the wireless chip's and goes into the
    // initramfs. The pin is the SHA-512, like the other packages of this archive; the SHA-256 of
    // the package, which the design names, is
    // 56b6f8792fb27bcc22f101a5a0d27af637e0d13e85dfc0fde5ff140abc929b0f. Its data archive is
    // gzip, which is why `deb::extract` reads that.
    Package {
        name: "boot firmware",
        url: "https://archive.raspberrypi.com/debian/pool/main/r/raspi-firmware/raspi-firmware_1.20260915-1_all.deb",
        file: "raspi-firmware_1.20260915-1_all.deb",
        digest: Digest::Sha512(
            "4558b24a88ecbd29b10eca8d18d6852791d19b823f7cc964fd384761c56aab20670ae008595b8d428a8794c2c13efe4dd343adff7866298d265d3ef7106bd8d2",
        ),
        wanted: &[
            ("usr/lib/raspi-firmware/bootcode.bin", "boot/bootcode.bin"),
            ("usr/lib/raspi-firmware/start.elf", "boot/start.elf"),
            ("usr/lib/raspi-firmware/fixup.dat", "boot/fixup.dat"),
            (
                "usr/lib/raspi-firmware/LICENCE.broadcom",
                "boot/LICENCE.broadcom",
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
    use qberrypi::modules::{DEFAULT_TABLE, ModuleTable};
    use std::collections::HashSet;
    use std::path::{Component, Path};

    #[test]
    fn the_packages_produce_the_twenty_five_files_the_image_and_the_card_need() {
        let mut outputs: Vec<&str> = PACKAGES
            .iter()
            .flat_map(|package| package.wanted.iter().map(|(_, output)| *output))
            .collect();
        outputs.sort_unstable();

        assert_eq!(
            outputs,
            [
                "bcm2710-rpi-3-b-plus.dtb",
                "boot/LICENCE.broadcom",
                "boot/bootcode.bin",
                "boot/fixup.dat",
                "boot/start.elf",
                "firmware/brcm/brcmfmac43455-sdio.bin",
                "firmware/brcm/brcmfmac43455-sdio.clm_blob",
                "firmware/brcm/brcmfmac43455-sdio.txt",
                "firmware/regulatory.db",
                "firmware/regulatory.db.p7s",
                "kernel8.img",
                "modules/ads7846.ko",
                "modules/backlight.ko",
                "modules/brcmfmac-cyw.ko",
                "modules/brcmfmac.ko",
                "modules/brcmutil.ko",
                "modules/cfg80211.ko",
                "modules/fb_ili9486.ko",
                "modules/fbtft.ko",
                "modules/rfkill.ko",
                "modules/spi-bcm2835.ko",
                "ov-README",
                "ov-disable-bt.dtbo",
                "ov-overlay_map.dtb",
                "ov-qb-piscreen.dtbo",
            ]
        );
    }

    #[test]
    fn the_overlay_files_come_from_the_kernel_release_the_device_tree_does() {
        let kernel = &PACKAGES[0];
        let member = |output: &str| {
            kernel
                .wanted
                .iter()
                .find(|(_, out)| *out == output)
                .map(|(member, _)| *member)
                .unwrap_or_else(|| panic!("{output} is not taken from the kernel package"))
        };
        let tree = member("bcm2710-rpi-3-b-plus.dtb");
        let dtb_folder = tree
            .strip_suffix("broadcom/bcm2710-rpi-3-b-plus.dtb")
            .unwrap();
        // The overlays sit beside the device tree's folder, under the same release.
        let overlays = format!("{dtb_folder}overlays/");
        assert_eq!(member("ov-README"), format!("{overlays}README"));
        assert_eq!(
            member("ov-overlay_map.dtb"),
            format!("{overlays}overlay_map.dtb")
        );
        assert_eq!(
            member("ov-qb-piscreen.dtbo"),
            format!("{overlays}piscreen.dtbo")
        );
        assert_eq!(
            member("ov-disable-bt.dtbo"),
            format!("{overlays}disable-bt.dtbo")
        );
    }

    #[test]
    fn the_boot_firmware_is_taken_from_its_package_into_the_folder_the_image_reads() {
        use crate::image::{FIRMWARE_FILES, FIRMWARE_FOLDER};
        let package = PACKAGES
            .iter()
            .find(|package| package.name == "boot firmware")
            .expect("the boot firmware is pinned");
        let folder = FIRMWARE_FOLDER
            .strip_prefix("vendor-cache/extracted/")
            .expect("the image reads what fetch extracted");

        // Each file the image needs is taken from the package's firmware folder, by its own name.
        let wanted: Vec<(&str, &str)> = package.wanted.to_vec();
        let expected: Vec<(String, String)> = FIRMWARE_FILES
            .iter()
            .map(|name| {
                (
                    format!("usr/lib/raspi-firmware/{name}"),
                    format!("{folder}/{name}"),
                )
            })
            .collect();
        assert_eq!(
            wanted,
            expected
                .iter()
                .map(|(member, output)| (member.as_str(), output.as_str()))
                .collect::<Vec<_>>()
        );
        // The package is the one of the design, and the wireless firmware stays a package of its own.
        assert_eq!(package.file, "raspi-firmware_1.20260915-1_all.deb");
        assert!(
            package
                .url
                .starts_with("https://archive.raspberrypi.com/debian/")
        );
        assert!(
            matches!(&package.digest, Digest::Sha512(sum) if sum.starts_with("4558b24a88ecbd29")),
            "the pin is the design's package"
        );
        assert_eq!(
            PACKAGES
                .iter()
                .filter(|p| p.name.contains("firmware"))
                .count(),
            2
        );
    }

    #[test]
    fn every_module_the_table_names_is_fetched() {
        let outputs: Vec<&str> = PACKAGES
            .iter()
            .flat_map(|package| package.wanted.iter().map(|(_, output)| *output))
            .collect();
        for file in ModuleTable::parse(DEFAULT_TABLE).unwrap().files() {
            assert!(
                outputs.contains(&format!("modules/{file}").as_str()),
                "{file}"
            );
        }
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
