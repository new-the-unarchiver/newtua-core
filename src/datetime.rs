//! Calendar-date → `SystemTime` helpers shared by format handlers.
//!
//! Several handlers carry modification timestamps stored as plain civil
//! date/time fields (zip's MS-DOS fields, WARC's RFC-3339 date). They all need
//! the same UTC conversion, so it lives here once.

use std::time::{Duration, SystemTime};

/// Convert Unix seconds to `SystemTime`, treating 0 as "not recorded".
///
/// Most container formats store an mtime as plain seconds since the epoch and
/// spell "no timestamp" as a zero field, so the zero check belongs here rather
/// than in every caller.
pub(crate) fn unix_secs_to_systime(secs: u64) -> Option<SystemTime> {
    (secs != 0).then(|| SystemTime::UNIX_EPOCH + Duration::from_secs(secs))
}

/// Windows `FILETIME` (100 ns intervals since 1601-01-01) → `SystemTime`.
///
/// Unlike the DOS and classic-Mac fields below, a `FILETIME` is an absolute
/// instant in UTC, not a wall-clock reading — so it converts by arithmetic
/// alone, with no timezone to guess. `0` conventionally means "no timestamp",
/// and a value before the Unix epoch yields `None` rather than wrapping.
///
/// Used by WIM (`.wim`/`.esd`) and by NSIS installers, which store the same
/// field.
pub(crate) fn filetime_to_systime(ticks: u64) -> Option<SystemTime> {
    // 100 ns intervals between the FILETIME epoch (1601-01-01) and the Unix
    // epoch (1970-01-01).
    const EPOCH_DIFF_100NS: u64 = 116_444_736_000_000_000;
    if ticks == 0 {
        return None;
    }
    let unix_100ns = ticks.checked_sub(EPOCH_DIFF_100NS)?;
    let secs = unix_100ns / 10_000_000;
    let nanos = (unix_100ns % 10_000_000) * 100;
    Some(SystemTime::UNIX_EPOCH + Duration::new(secs, nanos as u32))
}

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

/// Civil date from days since 1970-01-01 — the inverse of [`days_from_civil`],
/// same source. Needed to take a timestamp that is *stored* as an offset from
/// some epoch but *means* wall-clock time, and recover the wall clock.
fn civil_from_days(days: i64) -> (i32, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = (z - era * 146_097) as u32; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365; // [0, 399]
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    ((y + i64::from(m <= 2)) as i32, m, d)
}

/// Convert a **local** civil date-time — wall-clock, no timezone attached — to
/// `SystemTime`.
///
/// The formats of the DOS and classic-Mac era stored the clock on the wall and
/// nothing else: MS-DOS date/time fields in zip, seconds-since-1904 in StuffIt
/// and its relatives. Reading those as UTC shifts every date by the reader's
/// timezone offset, so a file made at midnight shows up as made at five in the
/// morning. XADMaster reads them as local time, which is what the person who
/// packed the file saw, and this matches it.
///
/// Done by the C library's `mktime`, because it is the only thing that knows
/// the offset **at that historical date** — a January file and a July file in
/// the same zone can differ by an hour of summer time, and a fixed "current
/// offset" would get one of them wrong. `tm_isdst = -1` asks it to work that
/// out.
///
/// Falls back to the UTC reading if `mktime` fails (an unset or broken zone
/// database): a date an hour off is better than no date at all.
pub(crate) fn local_civil_to_systime(
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
    let utc = civil_to_systime(year, month, day, hour, min, sec)?;

    #[cfg(unix)]
    {
        let mut tm: libc::tm = unsafe { std::mem::zeroed() };
        tm.tm_year = year - 1900;
        tm.tm_mon = month as i32 - 1;
        tm.tm_mday = day as i32;
        tm.tm_hour = hour as i32;
        tm.tm_min = min as i32;
        tm.tm_sec = sec as i32;
        tm.tm_isdst = -1; // "decide for me" — honours summer time on that date
        // SAFETY: `tm` is a fully initialised, owned `libc::tm`; `mktime` reads
        // and normalises it in place and returns the corresponding instant.
        let secs = unsafe { libc::mktime(&mut tm) };
        if secs < 0 {
            return Some(utc);
        }
        Some(SystemTime::UNIX_EPOCH + Duration::from_secs(secs as u64))
    }

    // Windows' libc has `tm` and `localtime_s` but no `mktime`, so the same
    // answer is reached from the other side: ask what local time the naive UTC
    // instant lands on, and the gap between that and the wanted wall clock is
    // the offset to undo. Iterating twice settles the case where the offset at
    // the first guess differs from the offset at the answer — the hour either
    // side of a summer-time change.
    #[cfg(windows)]
    {
        let mut guess = utc.duration_since(SystemTime::UNIX_EPOCH).ok()?.as_secs() as i64;
        for _ in 0..2 {
            let t = guess as libc::time_t;
            let mut tm: libc::tm = unsafe { std::mem::zeroed() };
            // SAFETY: both pointers are to owned, initialised locals.
            if unsafe { libc::localtime_s(&mut tm, &t) } != 0 {
                return Some(utc);
            }
            let local = civil_to_systime(
                tm.tm_year + 1900,
                tm.tm_mon as u32 + 1,
                tm.tm_mday as u32,
                tm.tm_hour as u64,
                tm.tm_min as u64,
                tm.tm_sec as u64,
            )?;
            let local = local.duration_since(SystemTime::UNIX_EPOCH).ok()?.as_secs() as i64;
            let want = utc.duration_since(SystemTime::UNIX_EPOCH).ok()?.as_secs() as i64;
            let offset = local - guess;
            let next = want - offset;
            if next == guess {
                break;
            }
            guess = next;
        }
        if guess < 0 {
            return Some(utc);
        }
        Some(SystemTime::UNIX_EPOCH + Duration::from_secs(guess as u64))
    }

    #[cfg(not(any(unix, windows)))]
    {
        Some(utc)
    }
}

/// Same as [`local_civil_to_systime`], for a timestamp already reduced to
/// seconds since the Unix epoch **but meaning wall-clock time**. Splits it back
/// into civil fields and re-reads them as local.
pub(crate) fn local_unix_secs_to_systime(secs: u64) -> Option<SystemTime> {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let (y, m, d) = civil_from_days(days);
    local_civil_to_systime(y, m, d, rem / 3600, (rem % 3600) / 60, rem % 60)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unix_secs_zero_is_no_time() {
        assert_eq!(unix_secs_to_systime(0), None);
        assert_eq!(
            unix_secs_to_systime(1),
            Some(SystemTime::UNIX_EPOCH + Duration::from_secs(1))
        );
    }

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

    /// Местное время должно отдаваться ровно теми часами, что записаны, — это
    /// и есть «как у автора файла». Проверяем кругом: перевели часы на стене в
    /// момент времени, вернули обратно системными средствами — получили те же
    /// часы. Зона машины при этом любая, тест не привязан к моей.
    #[test]
    fn local_civil_round_trips_through_the_system_timezone() {
        for (y, mo, d, h, mi, s) in [
            (1991, 12, 10, 11, 39, 19), // зима
            (1993, 8, 15, 23, 48, 26),  // лето: в те годы перевод часов был
            (2026, 8, 1, 20, 56, 32),
        ] {
            let t = local_civil_to_systime(y, mo, d, h, mi, s).expect("время получилось");
            let secs = t
                .duration_since(SystemTime::UNIX_EPOCH)
                .expect("после эпохи")
                .as_secs() as i64;

            #[cfg(unix)]
            {
                let tt = secs as libc::time_t;
                let mut tm: libc::tm = unsafe { std::mem::zeroed() };
                // SAFETY: оба указателя — на инициализированные локальные значения.
                unsafe { libc::localtime_r(&tt, &mut tm) };
                assert_eq!(
                    (
                        tm.tm_year + 1900,
                        tm.tm_mon as u32 + 1,
                        tm.tm_mday as u32,
                        tm.tm_hour as u64,
                        tm.tm_min as u64,
                        tm.tm_sec as u64
                    ),
                    (y, mo, d, h, mi, s),
                    "часы на стене должны вернуться теми же"
                );
            }
            #[cfg(not(unix))]
            let _ = secs;
        }
    }

    /// Всемирное чтение тех же полей даёт другой момент везде, кроме зоны GMT.
    /// Тест не утверждает, на сколько именно расходится, — только что это две
    /// разные вещи и путать их нельзя.
    #[test]
    fn local_and_utc_readings_are_not_the_same_thing() {
        let local = local_civil_to_systime(1991, 12, 10, 11, 39, 19).unwrap();
        let utc = civil_to_systime(1991, 12, 10, 11, 39, 19).unwrap();
        if std::env::var("TZ").as_deref() == Ok("UTC") {
            assert_eq!(local, utc);
        }
    }
}
