//! Deterministic partitioned sum-of-squares workload for `getter.abi.v1`.
//!
//! A task input is exactly `start:end` in ASCII decimal, with `end` exclusive
//! and both endpoints fitting in `u128`. The handler iterates over every value
//! in the range (it does not use a closed-form shortcut), sums `value * value`
//! with checked arithmetic, and emits exactly:
//!
//! ```text
//! {"value":"<u128-decimal>"}
//! ```
//!
//! There is no whitespace and no trailing newline. The output is therefore
//! deterministic for a valid input and can be verified with SHA-256.

use getter_workload_sdk::getter_workload;

/// Parses the strict `start:end` task input format.
///
/// The input must contain exactly one `:`, both endpoints must be non-empty
/// ASCII decimal integers that fit in `u128`, and `start` must not exceed
/// `end`. Leading zeroes are accepted; signs, whitespace, and every other byte
/// are rejected with a panic (which the Wasm host records as a trap).
fn parse_range(input: &[u8]) -> (u128, u128) {
    let mut separator = None;
    for (index, &byte) in input.iter().enumerate() {
        if byte == b':' {
            if separator.is_some() {
                panic!("sum-squares: task input must contain exactly one ':'");
            }
            separator = Some(index);
        }
    }

    let Some(separator) = separator else {
        panic!("sum-squares: task input must have the form start:end");
    };

    let start = parse_decimal(&input[..separator]);
    let end = parse_decimal(&input[separator + 1..]);
    if start > end {
        panic!("sum-squares: range start must not exceed range end");
    }

    (start, end)
}

/// Parses a non-empty ASCII decimal integer into `u128`.
fn parse_decimal(bytes: &[u8]) -> u128 {
    if bytes.is_empty() {
        panic!("sum-squares: range endpoints must not be empty");
    }

    let mut value = 0_u128;
    for &byte in bytes {
        if !byte.is_ascii_digit() {
            panic!("sum-squares: range endpoints must be ASCII decimal integers");
        }
        let digit = u128::from(byte - b'0');
        value = match value
            .checked_mul(10)
            .and_then(|scaled| scaled.checked_add(digit))
        {
            Some(parsed) => parsed,
            None => panic!("sum-squares: range endpoint does not fit in u128"),
        };
    }

    value
}

/// Sums the squares of every integer in `[start, end)` by iterating.
///
/// The workload intentionally computes each square and accumulates it one
/// value at a time. Checked arithmetic turns a range whose mathematical result
/// does not fit in `u128` into a trap instead of a silently wrapped value.
fn sum_squares_in_range(start: u128, end: u128) -> u128 {
    let mut total = 0_u128;
    let mut value = start;

    while value < end {
        let square = match value.checked_mul(value) {
            Some(square) => square,
            None => panic!("sum-squares: square overflows u128"),
        };
        total = match total.checked_add(square) {
            Some(next) => next,
            None => panic!("sum-squares: accumulated sum of squares overflows u128"),
        };
        // `value < end <= u128::MAX`, so incrementing cannot overflow here.
        value += 1;
    }

    total
}

/// The example handler: parse the range, sum its squares, and format the
/// canonical JSON output bytes.
///
/// This function is public so host tests can exercise the same code that the
/// generated `getter_execute` export calls.
pub fn sum_squares(input: &[u8]) -> Vec<u8> {
    let (start, end) = parse_range(input);
    let total = sum_squares_in_range(start, end);
    format!("{{\"value\":\"{total}\"}}").into_bytes()
}

getter_workload!(sum_squares);

#[cfg(test)]
mod tests {
    use super::{parse_decimal, parse_range, sum_squares, sum_squares_in_range};

    #[test]
    fn parses_a_simple_range() {
        assert_eq!(parse_range(b"0:5"), (0, 5));
    }

    #[test]
    fn parses_large_u128_endpoints() {
        let maximum = u128::MAX;
        let input = format!("0:{maximum}");
        assert_eq!(parse_range(input.as_bytes()), (0, maximum));
        assert_eq!(parse_decimal(maximum.to_string().as_bytes()), u128::MAX);
    }

    #[test]
    fn accepts_leading_zeroes_and_empty_ranges() {
        assert_eq!(parse_range(b"0000:0005"), (0, 5));
        assert_eq!(parse_range(b"7:7"), (7, 7));
        assert_eq!(sum_squares(b"7:7"), br#"{"value":"0"}"#.to_vec());
    }

    #[test]
    fn iterates_over_the_whole_range() {
        assert_eq!(sum_squares_in_range(0, 10), 285);
        assert_eq!(sum_squares_in_range(10, 12), 221);
        assert_eq!(sum_squares_in_range(5, 5), 0);

        let count = 100_000_u128;
        let expected = (count - 1) * count * (2 * count - 1) / 6;
        assert_eq!(sum_squares_in_range(0, count), expected);
    }

    #[test]
    fn emits_exact_canonical_bytes() {
        assert_eq!(sum_squares(b"0:10"), br#"{"value":"285"}"#.to_vec());
        assert_eq!(sum_squares(b"10:12"), br#"{"value":"221"}"#.to_vec());
        assert_eq!(sum_squares(b"0:1"), br#"{"value":"0"}"#.to_vec());
    }

    #[test]
    #[should_panic(expected = "must contain exactly one ':'")]
    fn rejects_multiple_separators() {
        let _ = sum_squares(b"0:1:2");
    }

    #[test]
    #[should_panic(expected = "must have the form start:end")]
    fn rejects_missing_separator() {
        let _ = sum_squares(b"12");
    }

    #[test]
    #[should_panic(expected = "must not be empty")]
    fn rejects_empty_start() {
        let _ = sum_squares(b":12");
    }

    #[test]
    #[should_panic(expected = "must not be empty")]
    fn rejects_empty_end() {
        let _ = sum_squares(b"12:");
    }

    #[test]
    #[should_panic(expected = "must be ASCII decimal integers")]
    fn rejects_whitespace() {
        let _ = sum_squares(b"1: 2");
    }

    #[test]
    #[should_panic(expected = "must be ASCII decimal integers")]
    fn rejects_signs() {
        let _ = sum_squares(b"+1:2");
    }

    #[test]
    #[should_panic(expected = "must not exceed range end")]
    fn rejects_descending_ranges() {
        let _ = sum_squares(b"9:8");
    }

    #[test]
    #[should_panic(expected = "range endpoint does not fit in u128")]
    fn rejects_endpoints_larger_than_u128() {
        // 2^128, one past u128::MAX.
        let _ = sum_squares(b"0:340282366920938463463374607431768211456");
    }

    #[test]
    #[should_panic(expected = "square overflows u128")]
    fn rejects_overflowing_squares() {
        let _ = sum_squares_in_range(u128::MAX - 1, u128::MAX);
    }
}
