//! Calendar-date → `SystemTime` helpers shared by format handlers.
//!
//! Several handlers carry modification timestamps stored as plain civil
//! date/time fields (zip's MS-DOS fields, WARC's RFC-3339 date). They all need
//! the same UTC conversion, so it lives here once.

use std::time::{Duration, SystemTime};

/// Convert a UTC civil date-time to `SystemTime`.
///
/// Returns `None` for out-of-range fields or pre-epoch dates (so a crafted
/// timestamp can never panic or index out of bounds — it just yields no time).
pub(crate) fn civil_to_systime(
    year: i32,
    month: u32,
    day: u32,
    hour: u64,
    min: u64,
    sec: u64,
) -> Option<SystemTime> {
    if year < 1970 || !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    let days = days_from_civil(year, month, day)?;
    let secs = days * 86400 + hour * 3600 + min * 60 + sec;
    Some(SystemTime::UNIX_EPOCH + Duration::from_secs(secs))
}

/// Days since 1970-01-01 for a civil date.
/// Algorithm from <http://howardhinnant.github.io/date_algorithms.html>.
/// Returns `None` for pre-epoch dates.
fn days_from_civil(y: i32, m: u32, d: u32) -> Option<u64> {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = (y - era * 400) as u32; // [0, 399]
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1; // [0, 365]
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
    let days_since_epoch = era as i64 * 146097 + doe as i64 - 719468;
    if days_since_epoch < 0 {
        None
    } else {
        Some(days_since_epoch as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn days_from_civil_epoch_and_known_date() {
        assert_eq!(days_from_civil(1970, 1, 1), Some(0));
        // 2000-01-01 is 10957 days after 1970-01-01.
        assert_eq!(days_from_civil(2000, 1, 1), Some(10957));
        assert_eq!(days_from_civil(1969, 12, 31), None);
    }

    #[test]
    fn civil_to_systime_valid_and_out_of_range() {
        assert_eq!(
            civil_to_systime(1970, 1, 1, 0, 0, 0),
            Some(SystemTime::UNIX_EPOCH)
        );
        assert_eq!(
            civil_to_systime(1970, 1, 1, 0, 1, 0),
            Some(SystemTime::UNIX_EPOCH + Duration::from_secs(60))
        );
        assert!(civil_to_systime(2020, 6, 15, 12, 30, 0).is_some());
        // Out-of-range fields and pre-epoch → None (never a panic).
        assert_eq!(civil_to_systime(2020, 13, 1, 0, 0, 0), None);
        assert_eq!(civil_to_systime(2020, 0, 1, 0, 0, 0), None);
        assert_eq!(civil_to_systime(1969, 12, 31, 23, 59, 59), None);
    }
}
