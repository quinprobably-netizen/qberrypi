//! `cargo xtask hash-password`: turns the password for the Pi-hole API's login into the
//! `password_hash` line that `qberrypi.toml` holds under `[api]`.
//!
//! The password is read from standard input, never from a terminal and never from an argument,
//! and is never printed; its buffers are wiped when they are dropped.
//!
//! A password that could never log in is refused here, not found out at the first login: one that
//! is not UTF-8, which qnet cannot send in JSON, and one whose login request would be over the
//! body that the API reads.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{self, IsTerminal, Read, Write};

use anyhow::{Context, Result, bail, ensure};
use qberrypi::api::http::MAX_BODY;
use qberrypi::api::password::PasswordHash;
use zeroize::Zeroizing;

/// The most bytes of password that standard input may hold, before the line ending.
const MAX_INPUT: usize = 64 * 1024;

/// How much of standard input is read: the longest password, a `\r\n` after it, and one byte more
/// to tell that there was too much.
const READ_LIMIT: usize = MAX_INPUT + 3;

/// The `password_hash = "..."` line for `password` with `salt`; an error for a password that
/// could never log in: an empty one, one that is not UTF-8 text, and one whose login request
/// would exceed [`MAX_BODY`]. No error holds any of the password.
pub fn hash_line(password: &[u8], salt: [u8; 16]) -> Result<String> {
    ensure!(!password.is_empty(), "the password is empty");
    let Ok(text) = std::str::from_utf8(password) else {
        bail!("the password must be UTF-8 text, as qnet sends it in JSON");
    };
    ensure!(
        login_body_len(text) <= MAX_BODY,
        "the password is too long: its login request would exceed 4 KiB"
    );
    let hash = PasswordHash::new(password, salt);
    Ok(format!("password_hash = \"{}\"", hash.to_text()))
}

/// The bytes of the login request body that qnet sends for `password`, `{"password":"..."}` in
/// compact JSON. They are only counted: no copy of the password is made, so none is left behind
/// unwiped.
fn login_body_len(password: &str) -> usize {
    /// A writer that keeps nothing but how much was written to it.
    struct Count(usize);
    impl Write for Count {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0 = self.0.saturating_add(bytes.len());
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let mut count = Count(0);
    match serde_json::to_writer(&mut count, &BTreeMap::from([("password", password)])) {
        Ok(()) => count.0,
        // Counting cannot fail; were it to, the password is not one to trust to the login.
        Err(_) => usize::MAX,
    }
}

/// Reads the password from standard input and prints its `password_hash` line on standard
/// output, with a hint for what to do with it on standard error.
pub fn run() -> Result<()> {
    let password = read_password_from_stdin()?;
    let line = hash_line(&password, random_salt()?)?;
    println!("{line}");
    eprintln!("put this line under [api] in qberrypi.toml");
    Ok(())
}

/// Reads the password from standard input, which must be a pipe or a file and not a terminal: it
/// is never typed where it would be shown, and never taken from an argument. Refuses more than
/// [`MAX_INPUT`] bytes. The buffer is wiped when it is dropped; no error holds any of it.
pub(crate) fn read_password_from_stdin() -> Result<Zeroizing<Vec<u8>>> {
    let stdin = io::stdin();
    ensure!(
        !stdin.is_terminal(),
        "pipe the password in (for example from the keyring that holds it); it is not read from a terminal, so it is never shown"
    );
    read_password(stdin.lock())
}

/// The body of the login request that `password` makes, `{"password":"..."}` in compact JSON, in a
/// buffer that is wiped when it is dropped; an error for a password that could never log in, as
/// [`hash_line`] refuses one: an empty one, one that is not UTF-8 text, and one whose login
/// request would exceed [`MAX_BODY`]. No error holds any of the password.
///
/// The buffer is made at its full size from the start, so that no copy of the password is left
/// behind in memory that was freed without being wiped.
pub(crate) fn login_body(password: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    ensure!(!password.is_empty(), "the password is empty");
    let Ok(text) = std::str::from_utf8(password) else {
        bail!("the password must be UTF-8 text, as the login sends it in JSON");
    };
    let length = login_body_len(text);
    ensure!(
        length <= MAX_BODY,
        "the password is too long: its login request would exceed 4 KiB"
    );
    let mut body = Zeroizing::new(Vec::with_capacity(length));
    serde_json::to_writer(&mut *body, &BTreeMap::from([("password", text)]))
        .context("cannot make the login request")?;
    Ok(body)
}

/// Reads all of `input` as the password, less one trailing `\n` or `\r\n`; refuses more than
/// [`MAX_INPUT`] bytes of password.
fn read_password(input: impl Read) -> Result<Zeroizing<Vec<u8>>> {
    // One buffer of the full size from the start, so that growing it never leaves a copy of the
    // password behind in memory that was freed without being wiped.
    let mut password = Zeroizing::new(Vec::with_capacity(READ_LIMIT));
    input
        .take(u64::try_from(READ_LIMIT).unwrap_or(u64::MAX))
        .read_to_end(&mut password)
        .context("reading the password from standard input")?;
    let ending = if password.ends_with(b"\r\n") {
        2
    } else {
        usize::from(password.ends_with(b"\n"))
    };
    let kept = password.len() - ending;
    password.truncate(kept);
    if password.len() > MAX_INPUT {
        bail!("the password is longer than 64 KiB");
    }
    Ok(password)
}

/// A salt of 16 random bytes from the kernel.
fn random_salt() -> Result<[u8; 16]> {
    let mut salt = [0; 16];
    File::open("/dev/urandom")
        .and_then(|mut random| random.read_exact(&mut salt))
        .context("reading 16 random bytes from /dev/urandom")?;
    Ok(salt)
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::io::Cursor;

    use qberrypi::api::http::MAX_BODY;
    use qberrypi::api::password::PasswordHash;

    const EXAMPLE: &str = include_str!("../../qberrypi.example.toml");

    #[test]
    fn the_line_is_the_hash_of_the_password_in_the_form_the_config_reads() {
        let line = hash_line(b"example", [0; 16]).unwrap();
        let text = PasswordHash::new(b"example", [0; 16]).to_text();
        assert_eq!(line, format!("password_hash = \"{text}\""));
        assert!(PasswordHash::parse(&text).is_some());
    }

    #[test]
    fn an_empty_password_gets_no_line() {
        let e = hash_line(b"", [0; 16]).unwrap_err();
        assert_eq!(e.to_string(), "the password is empty");
    }

    #[test]
    fn a_password_that_is_not_utf_8_gets_no_line() {
        // qnet sends the password as a JSON string, which is always UTF-8 text.
        for password in [&b"\xff\xfe"[..], b"ok\x80", b"\xc3", b"\xed\xa0\x80"] {
            let e = hash_line(password, [0; 16]).unwrap_err();
            assert_eq!(
                e.to_string(),
                "the password must be UTF-8 text, as qnet sends it in JSON"
            );
        }
        hash_line("p\u{e4}ssw\u{f6}rd \u{1f511}".as_bytes(), [0; 16]).unwrap();
    }

    #[test]
    fn the_length_that_counts_is_that_of_the_login_body_qnet_sends() {
        for password in [
            "",
            "x",
            "\"quoted\"",
            "back\\slash",
            "tab\tnew\nline",
            "\u{1}\u{1f}",
            "p\u{e4}ssw\u{f6}rd",
            "\u{1f511}",
            "\u{2028}",
        ] {
            let body = serde_json::to_vec(&serde_json::json!({ "password": password })).unwrap();
            assert_eq!(login_body_len(password), body.len(), "{password:?}");
        }
    }

    #[test]
    fn a_password_whose_login_request_would_pass_4_kib_gets_no_line() {
        assert_eq!(MAX_BODY, 4 * 1024, "the message says 4 KiB");
        let too_long = "the password is too long: its login request would exceed 4 KiB";
        // `{"password":""}` is 15 bytes, so a password of `MAX_BODY - 15` plain bytes just fits.
        let fits = "x".repeat(MAX_BODY - 15);
        hash_line(fits.as_bytes(), [0; 16]).unwrap();
        let over = "x".repeat(MAX_BODY - 14);
        let e = hash_line(over.as_bytes(), [0; 16]).unwrap_err();
        assert_eq!(e.to_string(), too_long);
        assert!(!format!("{e:#}").contains("xxx"), "{e:#}");
        // The body is JSON, so each quote is two bytes of it: 2,040 of them fit and 2,041 do not.
        hash_line("\"".repeat(2_040).as_bytes(), [0; 16]).unwrap();
        let e = hash_line("\"".repeat(2_041).as_bytes(), [0; 16]).unwrap_err();
        assert_eq!(e.to_string(), too_long);
        // The 64 KiB that standard input may hold is the outer bound, and is far over this one.
        let long = read_password(Cursor::new(vec![b'x'; MAX_INPUT])).unwrap();
        let e = hash_line(&long, [0; 16]).unwrap_err();
        assert_eq!(e.to_string(), too_long);
    }

    #[test]
    fn the_example_file_holds_the_line_for_the_password_example_and_a_salt_of_zeros() {
        let commented = EXAMPLE
            .lines()
            .find(|line| line.starts_with("# password_hash = "))
            .expect("the example file has a commented password_hash line");
        let line = commented.strip_prefix("# ").unwrap();
        assert_eq!(line, hash_line(b"example", [0; 16]).unwrap());
    }

    #[test]
    fn one_line_ending_is_dropped_and_nothing_else() {
        for (input, password) in [
            (&b"hunter2"[..], &b"hunter2"[..]),
            (b"hunter2\n", b"hunter2"),
            (b"hunter2\r\n", b"hunter2"),
            (b"hunter2\n\n", b"hunter2\n"),
            (b"hunter2\r\n\r\n", b"hunter2\r\n"),
            (b"hunter2\r", b"hunter2\r"),
            (b"hunter2\n\r", b"hunter2\n\r"),
            (b"  two words  \n", b"  two words  "),
            (b"a\nb\n", b"a\nb"),
            (b"\xff\xfe not text \x00\n", b"\xff\xfe not text \x00"),
            (b"\n", b""),
            (b"\r\n", b""),
            (b"", b""),
        ] {
            let read = read_password(Cursor::new(input)).unwrap();
            assert_eq!(read.as_slice(), password, "{input:?}");
        }
    }

    #[test]
    fn a_password_may_be_64_kib_and_no_more() {
        let most = vec![b'x'; MAX_INPUT];
        let read = read_password(Cursor::new(&most)).unwrap();
        // The buffer never had to grow, so no copy of the password was left in freed memory.
        assert_eq!((read.len(), read.capacity()), (MAX_INPUT, READ_LIMIT));
        let mut with_newline = most.clone();
        with_newline.push(b'\n');
        assert_eq!(
            read_password(Cursor::new(&with_newline)).unwrap().len(),
            MAX_INPUT
        );
        let mut too_long = most;
        too_long.extend_from_slice(b"yy");
        let e = read_password(Cursor::new(&too_long)).unwrap_err();
        assert_eq!(e.to_string(), "the password is longer than 64 KiB");
    }

    #[test]
    fn a_failed_read_is_reported_without_the_password() {
        struct Broken(bool);
        impl std::io::Read for Broken {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                if std::mem::replace(&mut self.0, true) {
                    Err(std::io::Error::other("the pipe broke"))
                } else {
                    buf[..6].copy_from_slice(b"secret");
                    Ok(6)
                }
            }
        }
        let e = read_password(Broken(false)).unwrap_err();
        assert!(!format!("{e:#}").contains("secret"), "{e:#}");
    }

    #[test]
    fn the_login_body_is_the_compact_json_that_qnet_sends_in_a_buffer_that_never_grew() {
        for password in [
            "x",
            "\"quoted\"",
            "back\\slash",
            "p\u{e4}ssw\u{f6}rd \u{1f511}",
        ] {
            let body = login_body(password.as_bytes()).unwrap();
            let expected = serde_json::to_vec(&serde_json::json!({ "password": password }));
            assert_eq!(
                body.as_slice(),
                expected.unwrap().as_slice(),
                "{password:?}"
            );
            assert_eq!(body.capacity(), body.len(), "{password:?}");
        }
    }

    #[test]
    fn a_password_that_could_never_log_in_makes_no_login_body_and_the_error_holds_none_of_it() {
        assert_eq!(
            login_body(b"").unwrap_err().to_string(),
            "the password is empty"
        );
        let e = login_body(b"secret\xff").unwrap_err();
        assert!(e.to_string().contains("UTF-8"), "{e}");
        assert!(!format!("{e:#}").contains("secret"), "{e:#}");
        login_body("x".repeat(MAX_BODY - 15).as_bytes()).unwrap();
        let e = login_body("x".repeat(MAX_BODY - 14).as_bytes()).unwrap_err();
        assert!(e.to_string().contains("exceed 4 KiB"), "{e}");
        assert!(!format!("{e:#}").contains("xxx"), "{e:#}");
    }
}
