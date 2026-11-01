//! RFC 3339 timestamps without a date-time dependency.

use std::time::{SystemTime, UNIX_EPOCH};

/// Format `time` as an RFC 3339 UTC timestamp with nanoseconds, e.g.
/// `2026-11-01T02:49:12.000000123Z`. Times before 1970 are clamped to the epoch.
pub fn rfc3339(time: SystemTime) -> String {
    let since_epoch = time.duration_since(UNIX_EPOCH).unwrap_or_default();
    let secs = since_epoch.as_secs();
    let days = i64::try_from(secs / 86_400).unwrap_or(i64::MAX);
    let (year, month, day) = civil_from_days(days);
    let rem = secs % 86_400;
    let (h, m, s) = (rem / 3600, rem % 3600 / 60, rem % 60);
    let nanos = since_epoch.subsec_nanos();
    format!("{year:04}-{month:02}-{day:02}T{h:02}:{m:02}:{s:02}.{nanos:09}Z")
}

/// Convert days since 1970-01-01 to a (year, month, day) in the proleptic Gregorian calendar.
///
/// This is Howard Hinnant's `civil_from_days` algorithm
/// (<https://howardhinnant.github.io/date_algorithms.html>). It shifts the year to start in March
/// so that the leap day is the last day of the year, which turns month lengths into arithmetic.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097); // day of era, [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // year of era, [0, 399]
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // day of year, [0, 365]
    let mp = (5 * doy + 2) / 153; // March-based month, [0, 11]
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    // Both values are small and non-negative by construction.
    (year, u32::try_from(month).unwrap_or(1), u32::try_from(day).unwrap_or(1))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn at(secs: u64) -> String {
        rfc3339(UNIX_EPOCH + Duration::from_secs(secs))
    }

    #[test]
    fn known_dates() {
        assert_eq!(at(0), "1970-01-01T00:00:00.000000000Z");
        assert_eq!(at(951_782_400), "2000-02-29T00:00:00.000000000Z");
        assert_eq!(at(1_700_000_000), "2023-11-14T22:13:20.000000000Z");
        assert_eq!(at(4_107_542_399), "2100-02-28T23:59:59.000000000Z");
    }

    #[test]
    fn nanoseconds_are_zero_padded() {
        let t = UNIX_EPOCH + Duration::new(0, 123);
        assert_eq!(rfc3339(t), "1970-01-01T00:00:00.000000123Z");
    }
}
