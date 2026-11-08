//! Exact decimal amount parsing, as Bitcoin Core's `AmountFromValue` does it.
//!
//! script_tests.json gives the amount of witness tests as a JSON number in BTC (for example
//! `0.00000001`). Core reads the number's text with `ParseFixedPoint(text, 8)` and then requires
//! `MoneyRange`. This module ports `ParseFixedPoint` (src/util/strencodings.cpp) digit by digit, so
//! the value never passes through a binary floating point number.

/// 10^18 - 1, the largest arbitrary decimal that fits in an i64 (Core's UPPER_BOUND).
const UPPER_BOUND: i64 = 1_000_000_000_000_000_000 - 1;
const MAX_MONEY: i64 = 21_000_000 * 100_000_000;

fn process_mantissa_digit(ch: u8, mantissa: &mut i64, mantissa_tzeros: &mut i64) -> bool {
    if ch == b'0' {
        *mantissa_tzeros += 1;
    } else {
        for _ in 0..=*mantissa_tzeros {
            if *mantissa > UPPER_BOUND / 10 {
                return false;
            }
            *mantissa *= 10;
        }
        *mantissa += (ch - b'0') as i64;
        *mantissa_tzeros = 0;
    }
    true
}

/// Port of Core's `ParseFixedPoint(val, decimals, &amount)`.
pub fn parse_fixed_point(val: &str, decimals: i64) -> Option<i64> {
    let v = val.as_bytes();
    let end = v.len();
    let mut ptr = 0usize;
    let mut mantissa: i64 = 0;
    let mut exponent: i64 = 0;
    let mut mantissa_tzeros: i64 = 0;
    let mut mantissa_sign = false;
    let mut exponent_sign = false;
    let mut point_ofs: i64 = 0;
    let is_digit = |c: u8| c.is_ascii_digit();

    if ptr < end && v[ptr] == b'-' {
        mantissa_sign = true;
        ptr += 1;
    }
    if ptr < end {
        if v[ptr] == b'0' {
            ptr += 1; // a single leading 0
        } else if (b'1'..=b'9').contains(&v[ptr]) {
            while ptr < end && is_digit(v[ptr]) {
                if !process_mantissa_digit(v[ptr], &mut mantissa, &mut mantissa_tzeros) {
                    return None;
                }
                ptr += 1;
            }
        } else {
            return None;
        }
    } else {
        return None;
    }
    if ptr < end && v[ptr] == b'.' {
        ptr += 1;
        if ptr < end && is_digit(v[ptr]) {
            while ptr < end && is_digit(v[ptr]) {
                if !process_mantissa_digit(v[ptr], &mut mantissa, &mut mantissa_tzeros) {
                    return None;
                }
                ptr += 1;
                point_ofs += 1;
            }
        } else {
            return None;
        }
    }
    if ptr < end && (v[ptr] == b'e' || v[ptr] == b'E') {
        ptr += 1;
        if ptr < end && v[ptr] == b'+' {
            ptr += 1;
        } else if ptr < end && v[ptr] == b'-' {
            exponent_sign = true;
            ptr += 1;
        }
        if ptr < end && is_digit(v[ptr]) {
            while ptr < end && is_digit(v[ptr]) {
                if exponent > UPPER_BOUND / 10 {
                    return None;
                }
                exponent = exponent * 10 + (v[ptr] - b'0') as i64;
                ptr += 1;
            }
        } else {
            return None;
        }
    }
    if ptr != end {
        return None;
    }
    if exponent_sign {
        exponent = -exponent;
    }
    exponent = exponent - point_ofs + mantissa_tzeros;
    if mantissa_sign {
        mantissa = -mantissa;
    }
    exponent += decimals;
    if !(0..18).contains(&exponent) {
        return None;
    }
    for _ in 0..exponent {
        if !(-(UPPER_BOUND / 10)..=UPPER_BOUND / 10).contains(&mantissa) {
            return None;
        }
        mantissa *= 10;
    }
    if !(-UPPER_BOUND..=UPPER_BOUND).contains(&mantissa) {
        return None;
    }
    Some(mantissa)
}

/// Core's `AmountFromValue` for a JSON number given as its exact source text: satoshis.
pub fn amount_from_btc_text(text: &str) -> Result<i64, String> {
    let sats = parse_fixed_point(text, 8).ok_or_else(|| format!("invalid amount {text}"))?;
    if !(0..=MAX_MONEY).contains(&sats) {
        return Err(format!("amount out of range: {text}"));
    }
    Ok(sats)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_like_core() {
        // Cases from Core's src/test/util_tests.cpp (test_ParseFixedPoint).
        assert_eq!(parse_fixed_point("0", 8), Some(0));
        assert_eq!(parse_fixed_point("1", 8), Some(100000000));
        assert_eq!(parse_fixed_point("0.0", 8), Some(0));
        assert_eq!(parse_fixed_point("-0.1", 8), Some(-10000000));
        assert_eq!(parse_fixed_point("1.1", 8), Some(110000000));
        assert_eq!(parse_fixed_point("1.10000000000000000", 8), Some(110000000));
        assert_eq!(parse_fixed_point("1.1e1", 8), Some(1100000000));
        assert_eq!(parse_fixed_point("1.1e-1", 8), Some(11000000));
        assert_eq!(parse_fixed_point("1000", 8), Some(100000000000));
        assert_eq!(parse_fixed_point("-1000", 8), Some(-100000000000));
        assert_eq!(parse_fixed_point("0.00000001", 8), Some(1));
        assert_eq!(parse_fixed_point("0.0000000100000000", 8), Some(1));
        assert_eq!(parse_fixed_point("-0.00000001", 8), Some(-1));
        assert_eq!(
            parse_fixed_point("1000000000.00000001", 8),
            Some(100000000000000001)
        );
        assert_eq!(
            parse_fixed_point("9999999999.99999999", 8),
            Some(999999999999999999)
        );
        assert_eq!(
            parse_fixed_point("-9999999999.99999999", 8),
            Some(-999999999999999999)
        );
        assert_eq!(parse_fixed_point("", 8), None);
        assert_eq!(parse_fixed_point("-", 8), None);
        assert_eq!(parse_fixed_point("a-1000", 8), None);
        assert_eq!(parse_fixed_point("-a1000", 8), None);
        assert_eq!(parse_fixed_point("-1000a", 8), None);
        assert_eq!(parse_fixed_point("-01000", 8), None);
        assert_eq!(parse_fixed_point("00.1", 8), None);
        assert_eq!(parse_fixed_point(".1", 8), None);
        assert_eq!(parse_fixed_point("--0.1", 8), None);
        assert_eq!(parse_fixed_point("0.000000001", 8), None);
        assert_eq!(parse_fixed_point("-0.000000001", 8), None);
        assert_eq!(parse_fixed_point("0.00000001000000001", 8), None);
        assert_eq!(parse_fixed_point("-10000000000.00000000", 8), None);
        assert_eq!(parse_fixed_point("10000000000.00000000", 8), None);
        assert_eq!(parse_fixed_point("-10000000000.00000001", 8), None);
        assert_eq!(parse_fixed_point("10000000000.00000001", 8), None);
        assert_eq!(parse_fixed_point("-10000000000.00000009", 8), None);
        assert_eq!(parse_fixed_point("10000000000.00000009", 8), None);
        assert_eq!(parse_fixed_point("-99999999999.99999999", 8), None);
        assert_eq!(parse_fixed_point("99999909999.09999999", 8), None);
        assert_eq!(parse_fixed_point("92233720368.54775807", 8), None);
        assert_eq!(parse_fixed_point("92233720368.54775808", 8), None);
        assert_eq!(parse_fixed_point("-92233720368.54775808", 8), None);
        assert_eq!(parse_fixed_point("-92233720368.54775809", 8), None);
        assert_eq!(parse_fixed_point("1.1e", 8), None);
        assert_eq!(parse_fixed_point("1.1e-", 8), None);
        assert_eq!(parse_fixed_point("1.", 8), None);
        assert_eq!(parse_fixed_point("0.001", 3), Some(1));
        assert_eq!(parse_fixed_point("0.0009", 3), None);
        assert_eq!(parse_fixed_point("31.00100001", 3), None);
        assert_eq!(parse_fixed_point("31.0011", 3), None);
        assert_eq!(parse_fixed_point("31.99999999", 3), None);
        assert_eq!(parse_fixed_point("31.999999999999999999999", 3), None);
        // Exponent form, which JSON allows.
        assert_eq!(parse_fixed_point("1e-8", 8), Some(1));
    }

    #[test]
    fn money_range() {
        assert_eq!(amount_from_btc_text("0.00000001"), Ok(1));
        assert_eq!(amount_from_btc_text("21000000"), Ok(MAX_MONEY));
        assert!(amount_from_btc_text("21000000.00000001").is_err());
        assert!(amount_from_btc_text("-0.00000001").is_err());
    }
}
