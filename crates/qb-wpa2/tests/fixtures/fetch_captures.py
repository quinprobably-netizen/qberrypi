#!/usr/bin/env python3
"""Fetch two published WPA2 handshake captures and extract what tests/captures.rs replays.

The capture tests check qb-wpa2 against a real access point and a real station, and against a
real network outside its scope. The captures are other people's files: one comes from a GPL-2.0
repository, the other has no clear licence, and this repository is MIT. So nothing of them is
committed, neither the files nor any frame, element, nonce, address or key taken or derived from
them. This script downloads each capture from its pinned URL, checks its pinned SHA-256, and
writes the byte strings the tests need to a git-ignored file. The tests are `#[ignore]`d and
read that file when they are asked for:

    python3 -I crates/qb-wpa2/tests/fixtures/fetch_captures.py
    cargo test -p qb-wpa2 -- --ignored

The script takes no arguments, may be started from any directory, and downloads nothing that is
already there with the right digest. It uses Python's standard library and the `openssl` command
line, and no qb-wpa2 code: the keys it writes are an independent check of the crate.

The captures:

    linksys     wpa2-psk-linksys.cap
      source    aircrack-ng test files (first shipped with coWPAtty)
      URL       https://raw.githubusercontent.com/aircrack-ng/aircrack-ng/7e2256f38f3590af4c19a6ae14ed79bab02242e6/test/wpa2-psk-linksys.cap
      SHA-256   e6a3a0f4ef454d5f881964220fe9f0e19dd9ab1c867f86bf0f85a25b416baccf
      network   name "linksys", passphrase "dictionary"; WPA2, CCMP pairwise and group
      packets   7 beacon, 46 association request, 50, 51, 53, 54 (messages 1 to 4)

    induction   wpa-Induction.pcap
      source    Wireshark wiki, SampleCaptures
      URL       https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/wpa-Induction.pcap
      SHA-256   2b57dca7fa2c3bd0e942060b546028d961bfb698fb12ed8b2947b13f88d170c8
      network   name "Coherer", passphrase "Induction"; mixed WPA/WPA2, CCMP pairwise, TKIP group
      packets   1 beacon, 89 (message 2, for its SNonce only), 92 (message 3)

Packets are numbered from 1. Everything is kept under vendor-cache/captures/ of the repository:

    linksys/wpa2-psk-linksys.cap     the download, alone in its directory
    induction/wpa-Induction.pcap     the download, alone in its directory
    frames.txt                       what the tests read

The downloads are untrusted data. They are read as bytes, hashed and sliced; the wrapped key data
of two frames is handed to `openssl enc` as an input file; nothing from them is executed.

frames.txt: a line that starts with `#` is a comment; every other line is a name, one space and
lower-case hex. The names, in this order:

    linksys.AA  linksys.SPA          the addresses of the access point and of the station
    linksys.AP_RSNE                  the RSN element of the beacon
    linksys.STA_RSNE                 the RSN element of the association request
    linksys.M1 .. linksys.M4         the four EAPOL-Key frames
    linksys.TK  linksys.GTK          the pairwise and the group key (computed)
    induction.AA  induction.SPA      the addresses
    induction.AP_RSNE                the RSN element of the beacon
    induction.SNONCE                 the nonce of the station's message 2
    induction.M3                     the EAPOL-Key frame of message 3
    induction.KEY_DATA               its key data, unwrapped (computed)

The computed values are written only after the MICs of linksys messages 2, 3 and 4 and of
induction message 3 have verified under the key derived from the passphrase.
"""
import hashlib, hmac, http.client, os, pathlib, subprocess, sys, tempfile
import urllib.error, urllib.request

CAPTURES = {
    "linksys": {
        "file": "wpa2-psk-linksys.cap",
        "url": "https://raw.githubusercontent.com/aircrack-ng/aircrack-ng/"
               "7e2256f38f3590af4c19a6ae14ed79bab02242e6/test/wpa2-psk-linksys.cap",
        "sha256": "e6a3a0f4ef454d5f881964220fe9f0e19dd9ab1c867f86bf0f85a25b416baccf",
        "ssid": b"linksys",
        "passphrase": b"dictionary",
    },
    "induction": {
        "file": "wpa-Induction.pcap",
        "url": "https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/"
               "wpa-Induction.pcap",
        "sha256": "2b57dca7fa2c3bd0e942060b546028d961bfb698fb12ed8b2947b13f88d170c8",
        "ssid": b"Coherer",
        "passphrase": b"Induction",
    },
}
# fixtures, tests, qb-wpa2, crates, and then the repository.
ROOT = pathlib.Path(__file__).resolve().parents[4]
USER_AGENT = "qb-wpa2-fetch-captures"
SIZE_LIMIT = 4 * 1024 * 1024
TIMEOUT_SECONDS = 60
BEACON, ASSOCIATION_REQUEST = 0x80, 0x00
# LLC/SNAP header of an 802.1X frame: the EAPOL frame follows it.
LLC_SNAP_EAPOL = b"\xaa\xaa\x03\x00\x00\x00\x88\x8e"
# Key information: the bits that tell the four messages apart, and their values in messages 1 to 4.
INSTALL, ACK, MIC, SECURE = 0x0040, 0x0080, 0x0100, 0x0200
MESSAGE = {1: ACK, 2: MIC, 3: INSTALL | ACK | MIC | SECURE, 4: MIC | SECURE}


def fail(message):
    """Ends the script with a message on standard error and exit status 1."""
    sys.exit(f"fetch_captures.py: {message}")


def cut(data, start, end, what):
    """data[start:end], or the end of the script if those bytes are not all there."""
    if not 0 <= start <= end <= len(data):
        fail(f"{what} is shorter than expected")
    return data[start:end]


class HttpsOnly(urllib.request.HTTPRedirectHandler):
    """Follows a redirect only to another https:// address."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not newurl.startswith("https://"):
            raise urllib.error.URLError("redirected to an address that is not https://")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def download(url):
    """The body of an HTTPS GET of `url`; the request says nothing but the fixed User-Agent."""
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    body = b""
    try:
        opener = urllib.request.build_opener(HttpsOnly)
        with opener.open(request, timeout=TIMEOUT_SECONDS) as response:
            if not response.geturl().startswith("https://"):
                fail(f"{url}: answered from an address that is not https://")
            while len(body) <= SIZE_LIMIT:
                block = response.read(min(65536, SIZE_LIMIT + 1 - len(body)))
                if not block:
                    break
                body += block
    except urllib.error.HTTPError as error:
        fail(f"{url}: HTTP status {error.code}")
    except (OSError, http.client.HTTPException) as error:
        fail(f"{url}: {type(error).__name__}: {error}")
    if len(body) > SIZE_LIMIT:
        fail(f"{url}: the response is larger than {SIZE_LIMIT} bytes")
    return body


def verified(name, capture, directory):
    """The bytes of one capture, whose SHA-256 is the pinned one: from disk, or else downloaded."""
    path = directory / name / capture["file"]
    if path.is_file():
        with open(path, "rb") as file:
            data = file.read(SIZE_LIMIT + 1)
        if hashlib.sha256(data).hexdigest() == capture["sha256"]:
            print(f"{name}: {path.name} already there, {len(data)} bytes,"
                  f" SHA-256 {capture['sha256']}")
            return data
    path.parent.mkdir(parents=True, exist_ok=True)
    data = download(capture["url"])
    partial = path.with_name(path.name + ".partial")
    partial.write_bytes(data)
    digest = hashlib.sha256(data).hexdigest()
    if digest != capture["sha256"]:
        partial.unlink()
        fail(f"{name}: {path.name} has the wrong SHA-256\n  expected {capture['sha256']}\n"
             f"  actual   {digest}")
    os.replace(partial, path)
    print(f"{name}: {path.name} downloaded, {len(data)} bytes, SHA-256 {digest}")
    return data


def packets(data, wanted, what):
    """The 802.11 frames with the numbers `wanted`, counted from 1, of a little-endian pcap."""
    header = cut(data, 0, 24, f"{what}: the pcap header")
    if header[:4] != b"\xd4\xc3\xb2\xa1":
        fail(f"{what}: not a little-endian pcap")
    link_type = int.from_bytes(header[20:24], "little")
    if link_type not in (105, 127):
        fail(f"{what}: neither 802.11 nor radiotap, but link type {link_type}")
    found, pos = {}, 24
    for number in range(1, max(wanted) + 1):
        where = f"{what}: packet {number}"
        size = int.from_bytes(cut(data, pos + 8, pos + 12, where), "little")
        frame = cut(data, pos + 16, pos + 16 + size, where)
        pos += 16 + size
        if number in wanted:
            if link_type == 127:
                skip = int.from_bytes(cut(frame, 2, 4, where), "little")
                frame = cut(frame, skip, len(frame), where)
            found[number] = frame
    return found


def management(frame, kind, fixed, what):
    """(receiver, transmitter, BSSID, RSN element) of a management frame of one kind.

    `fixed` is the number of bytes between its header and its elements."""
    head = cut(frame, 0, 24 + fixed, what)
    if head[0] != kind:
        fail(f"{what} is not the kind of frame expected there")
    rest = frame[24 + fixed:]
    while len(rest) >= 2:
        if rest[0] == 0x30:
            return head[4:10], head[10:16], head[16:22], cut(rest, 0, 2 + rest[1], what)
        rest = rest[2 + rest[1]:]
    fail(f"{what} has no RSN element")


def eapol_key(frame, message, what):
    """(receiver, transmitter, EAPOL-Key frame) of the data frame that carries message 1, 2, 3 or 4."""
    head = cut(frame, 0, 24, what)
    # Data or QoS data, to or from the access point, in the clear.
    if head[0] not in (0x08, 0x88) or head[1] & 0x03 not in (1, 2) or head[1] & 0x40:
        fail(f"{what} is not the kind of frame expected there")
    start = 24 + (2 if head[0] == 0x88 else 0)
    if cut(frame, start, start + 8, what) != LLC_SNAP_EAPOL:
        fail(f"{what} is not an EAPOL frame")
    start += 8
    length = int.from_bytes(cut(frame, start + 2, start + 4, what), "big")
    # What follows the declared length is link-layer padding or a frame check sequence.
    key = cut(frame, start, start + 4 + length, what)
    # 95 bytes of fixed fields, the last two of them the length of the key data.
    if key[1] != 3 or length < 95 or 99 + int.from_bytes(key[97:99], "big") > len(key):
        fail(f"{what} is not a whole EAPOL-Key frame")
    info = int.from_bytes(key[5:7], "big")
    if key[4] != 2 or info & 7 != 2 or info & (INSTALL | ACK | MIC | SECURE) != MESSAGE[message]:
        fail(f"{what} is not message {message} of a handshake under key descriptor version 2")
    return head[4:10], head[10:16], key


def prf(key, label, data, n):
    """The PRF of IEEE Std 802.11-2016 12.7.1.2, as in reference_handshake.py."""
    out = b""
    for i in range((n + 19) // 20):
        out += hmac.new(key, label + b"\0" + data + bytes([i]), hashlib.sha1).digest()
    return out[:n]


def pairwise_keys(capture, aa, spa, anonce, snonce):
    """(KCK, KEK, TK) from the passphrase and network name of `capture`."""
    pmk = hashlib.pbkdf2_hmac("sha1", capture["passphrase"], capture["ssid"], 4096, 32)
    ptk = prf(pmk, b"Pairwise key expansion",
              min(aa, spa) + max(aa, spa) + min(anonce, snonce) + max(anonce, snonce), 48)
    return ptk[:16], ptk[16:32], ptk[32:]


def check_mic(kck, key, what):
    """Ends the script unless the MIC of an EAPOL-Key frame verifies under `kck`."""
    mic = hmac.new(kck, key[:81] + bytes(16) + key[97:], hashlib.sha1).digest()[:16]
    if not hmac.compare_digest(mic, key[81:97]):
        fail(f"the MIC of {what} does not verify")


def unwrap(kek, key, what):
    """The key data of an EAPOL-Key frame after the AES key unwrap of RFC 3394, done by OpenSSL."""
    wrapped = key[99:99 + int.from_bytes(key[97:99], "big")]
    if len(wrapped) < 24 or len(wrapped) % 8:
        fail(f"the key data of {what} has no length a key wrap produces")
    with tempfile.TemporaryDirectory() as d:
        src, dst = os.path.join(d, "in"), os.path.join(d, "out")
        with open(src, "wb") as file:
            file.write(wrapped)
        try:
            done = subprocess.run(["openssl", "enc", "-d", "-id-aes128-wrap", "-K", kek.hex(),
                                   "-iv", "a6a6a6a6a6a6a6a6", "-in", src, "-out", dst],
                                  stdin=subprocess.DEVNULL, capture_output=True,
                                  timeout=TIMEOUT_SECONDS)
        except (OSError, subprocess.TimeoutExpired) as error:
            fail(f"openssl did not run: {type(error).__name__}: {error}")
        if done.returncode != 0:
            fail(f"openssl could not unwrap the key data of {what}")
        with open(dst, "rb") as file:
            plain = file.read()
    if len(plain) != len(wrapped) - 8:
        fail(f"the key data of {what} did not unwrap to its length less eight bytes")
    return plain


def group_key(plain, what):
    """The 16-byte key of the GTK KDE in unwrapped key data."""
    rest = plain
    # `dd 00` starts the padding.
    while len(rest) >= 2 and rest[:2] != b"\xdd\x00":
        element, rest = cut(rest, 0, 2 + rest[1], f"the key data of {what}"), rest[2 + rest[1]:]
        # OUI 00-0F-AC, data type 1; then the key id and a reserved byte.
        if element[0] == 0xDD and element[2:6] == b"\x00\x0f\xac\x01":
            if len(element) != 8 + 16:
                fail(f"the group key of {what} is not 16 bytes long")
            return element[8:]
    fail(f"the key data of {what} has no GTK KDE")


def linksys(data):
    """The entries of frames.txt that come from wpa2-psk-linksys.cap."""
    capture, packet = CAPTURES["linksys"], packets(data, {7, 46, 50, 51, 53, 54}, "linksys")
    _, _, aa, ap_rsne = management(packet[7], BEACON, 12, "linksys: packet 7")
    to, spa, bssid, sta_rsne = management(packet[46], ASSOCIATION_REQUEST, 4, "linksys: packet 46")
    if (to, bssid) != (aa, aa):
        fail("linksys: packet 46 is not addressed to the access point of packet 7")
    frames = {}
    for message, number in ((1, 50), (2, 51), (3, 53), (4, 54)):
        where = f"linksys: packet {number}"
        to, sender, frames[message] = eapol_key(packet[number], message, where)
        if (to, sender) != ((spa, aa) if message in (1, 3) else (aa, spa)):
            fail(f"linksys: packet {number} is not between the stations of packets 7 and 46")
    m1, m2, m3, m4 = (frames[message] for message in (1, 2, 3, 4))
    if m3[17:49] != m1[17:49]:
        fail("linksys: messages 1 and 3 carry different nonces")
    kck, kek, tk = pairwise_keys(capture, aa, spa, m1[17:49], m2[17:49])
    for message in (2, 3, 4):
        check_mic(kck, frames[message], f"linksys message {message}")
    gtk = group_key(unwrap(kek, m3, "linksys message 3"), "linksys message 3")
    return [("AA", aa), ("SPA", spa), ("AP_RSNE", ap_rsne), ("STA_RSNE", sta_rsne), ("M1", m1),
            ("M2", m2), ("M3", m3), ("M4", m4), ("TK", tk), ("GTK", gtk)]


def induction(data):
    """The entries of frames.txt that come from wpa-Induction.pcap."""
    capture, packet = CAPTURES["induction"], packets(data, {1, 89, 92}, "induction")
    _, _, aa, ap_rsne = management(packet[1], BEACON, 12, "induction: packet 1")
    to, spa, m2 = eapol_key(packet[89], 2, "induction: packet 89")
    if to != aa:
        fail("induction: packet 89 is not addressed to the access point of packet 1")
    to, sender, m3 = eapol_key(packet[92], 3, "induction: packet 92")
    if (to, sender) != (spa, aa):
        fail("induction: packet 92 is not between the stations of packets 1 and 89")
    snonce = m2[17:49]
    kck, kek, _ = pairwise_keys(capture, aa, spa, m3[17:49], snonce)
    check_mic(kck, m3, "induction message 3")
    key_data = unwrap(kek, m3, "induction message 3")
    return [("AA", aa), ("SPA", spa), ("AP_RSNE", ap_rsne), ("SNONCE", snonce), ("M3", m3),
            ("KEY_DATA", key_data)]


def main():
    if not (ROOT / "crates" / "qb-wpa2" / "Cargo.toml").is_file():
        fail(f"{ROOT} is not the repository this script belongs to")
    directory = ROOT / "vendor-cache" / "captures"
    data = {name: verified(name, capture, directory) for name, capture in CAPTURES.items()}
    lines = ["# Written by crates/qb-wpa2/tests/fixtures/fetch_captures.py from two published",
             "# captures. Other people's bytes: not to be committed.",
             "# Each line: a name, one space, lower-case hex."]
    for name, extract in (("linksys", linksys), ("induction", induction)):
        lines += [f"{name}.{entry} {value.hex()}" for entry, value in extract(data[name])]
    frames = directory / "frames.txt"
    partial = frames.with_name(frames.name + ".partial")
    partial.write_text("\n".join(lines) + "\n", encoding="ascii")
    os.replace(partial, frames)
    print(f"{frames}: {len(lines) - 3} entries written")
    print("now run: cargo test -p qb-wpa2 -- --ignored")


if __name__ == "__main__":
    try:
        main()
    except OSError as error:
        fail(f"{type(error).__name__}: {error}")
