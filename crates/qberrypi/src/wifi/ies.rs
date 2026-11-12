//! A walker over the information elements of a beacon or probe response.

/// The element id of the SSID element, the network's name.
pub const EID_SSID: u8 = 0;

/// The element id of the RSN element, which lists the ciphers and key management of a WPA2 network.
pub const EID_RSN: u8 = 48;

/// The element id of the RSN extension element.
pub const EID_RSNX: u8 = 244;

/// The first element with this id, whole: its id and length bytes included.
///
/// The list comes off the air. The walk ends, returning `None`, at the first element whose body would run
/// past the end of the list; the elements before it are still found.
pub fn element(ies: &[u8], id: u8) -> Option<&[u8]> {
    let mut rest = ies;
    while let &[element_id, length, ..] = rest {
        let (whole, tail) = rest.split_at_checked(2 + usize::from(length))?;
        if element_id == id {
            return Some(whole);
        }
        rest = tail;
    }
    None
}

/// The body of the first element with this id: `element` without its two header bytes.
pub fn body(ies: &[u8], id: u8) -> Option<&[u8]> {
    element(ies, id)?.get(2..)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    #[test]
    fn an_element_is_returned_whole() {
        let list = hex!("0003616263" "30140100000fac040100000fac040100000fac020000" "f40120");
        assert_eq!(element(&list, EID_RSN), Some(&list[5..27]));
        assert_eq!(body(&list, EID_SSID), Some(&b"abc"[..]));
        assert_eq!(element(&list, EID_RSNX), Some(&hex!("f40120")[..]));
        assert_eq!(element(&list, 7), None);
        assert_eq!(body(&hex!("0000"), EID_SSID), Some(&[][..]));
    }

    // Review Focus 5.
    #[test]
    fn a_list_that_overruns_ends_there() {
        let list = hex!("0003616263" "30ff0100"); // the second element claims 255 bytes
        assert_eq!(body(&list, EID_SSID), Some(&b"abc"[..]));
        assert_eq!(element(&list, EID_RSN), None);
        // No prefix of a well-formed list, and no list with one byte set to 0xff, makes the walker panic.
        let list = hex!("0003616263" "30140100000fac040100000fac040100000fac020000" "f40120");
        for id in [EID_SSID, EID_RSN, EID_RSNX] {
            for end in 0..=list.len() {
                let _ = element(&list[..end], id);
                let _ = body(&list[..end], id);
            }
            for index in 0..list.len() {
                let mut corrupted = list;
                corrupted[index] = 0xff;
                let _ = element(&corrupted, id);
                let _ = body(&corrupted, id);
            }
        }
    }
}
