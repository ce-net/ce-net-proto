//! Numbers with units, and time. CAL writes amounts the way people say them (`10MB`, `10m`,
//! `2026-12-01`) and compiles them to the integers a v3 link stores. Every unit has one meaning:
//! sizes are decimal SI (`MB` = 1 000 000 bytes, `MiB` = 1 048 576), durations are seconds,
//! minutes, hours, days and weeks, and every date and time is UTC.

/// `n` with an optional size or duration suffix, as an integer. `None` for anything else.
pub fn amount(s: &str) -> Option<u64> {
    let split = s.find(|c: char| !c.is_ascii_digit() && c != '_').unwrap_or(s.len());
    let (num, unit) = s.split_at(split);
    let num: String = num.chars().filter(|c| *c != '_').collect();
    if num.is_empty() {
        return None;
    }
    let n: u64 = num.parse().ok()?;
    let mul: u64 = match unit {
        "" | "B" => 1,
        "KB" => 1_000,
        "MB" => 1_000_000,
        "GB" => 1_000_000_000,
        "TB" => 1_000_000_000_000,
        "KiB" => 1 << 10,
        "MiB" => 1 << 20,
        "GiB" => 1 << 30,
        "TiB" => 1 << 40,
        "s" => 1,
        "m" => 60,
        "h" => 3_600,
        "d" => 86_400,
        "w" => 604_800,
        _ => return None,
    };
    n.checked_mul(mul)
}

/// A duration in seconds (`30s`, `10m`, `1h`, `7d`, `2w`, or plain seconds).
pub fn duration(s: &str) -> Option<u64> {
    let last = s.chars().last()?;
    if last.is_ascii_digit() || "smhdw".contains(last) { amount(s) } else { None }
}

/// A byte count (`512`, `10MB`, `1GiB`).
pub fn bytes(s: &str) -> Option<u64> {
    let last = s.chars().last()?;
    if last.is_ascii_digit() || last == 'B' { amount(s) } else { None }
}

/// The shortest exact duration spelling: `600` -> `10m`, `90` -> `90s`.
pub fn fmt_duration(s: u64) -> String {
    for (unit, n) in [("w", 604_800), ("d", 86_400), ("h", 3_600), ("m", 60)] {
        if s != 0 && s % n == 0 {
            return format!("{}{unit}", s / n);
        }
    }
    format!("{s}s")
}

/// The shortest exact decimal size spelling: `10_000_000` -> `10MB`.
pub fn fmt_bytes(b: u64) -> String {
    for (unit, n) in [("TB", 1_000_000_000_000u64), ("GB", 1_000_000_000), ("MB", 1_000_000), ("KB", 1_000)] {
        if b != 0 && b % n == 0 {
            return format!("{}{unit}", b / n);
        }
    }
    format!("{b}B")
}

/// Plain-English duration: `600` -> `10 minutes`.
pub fn say_duration(s: u64) -> String {
    for (unit, n) in [("week", 604_800), ("day", 86_400), ("hour", 3_600), ("minute", 60)] {
        if s != 0 && s % n == 0 {
            let k = s / n;
            return format!("{k} {unit}{}", if k == 1 { "" } else { "s" });
        }
    }
    format!("{s} second{}", if s == 1 { "" } else { "s" })
}

/// Plain-English size: `10_000_000` -> `10 MB (10000000 bytes)`.
pub fn say_bytes(b: u64) -> String {
    let short = fmt_bytes(b);
    if short.ends_with("KB") || short.ends_with("MB") || short.ends_with("GB") || short.ends_with("TB") {
        format!("{} {} ({b} bytes)", &short[..short.len() - 2], &short[short.len() - 2..])
    } else {
        format!("{b} bytes")
    }
}

// ---- dates (proleptic Gregorian, UTC), after Howard Hinnant's days_from_civil

fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m as i64 + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

fn days_in(y: i64, m: u32) -> u32 {
    match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        _ if (y % 4 == 0 && y % 100 != 0) || y % 400 == 0 => 29,
        _ => 28,
    }
}

/// `2026-12-01` (midnight UTC), `2026-12-01T12:30:00Z`, `2026-12-01T12:30Z`, or `@<unix secs>`.
pub fn time(s: &str) -> Option<u64> {
    if let Some(n) = s.strip_prefix('@') {
        return n.parse().ok();
    }
    let (date, clock) = match s.split_once('T') {
        Some((d, c)) => (d, Some(c.strip_suffix('Z')?)),
        None => (s, None),
    };
    let mut it = date.split('-');
    let (y, m, d) = (it.next()?, it.next()?, it.next()?);
    if it.next().is_some() || y.len() != 4 || m.len() != 2 || d.len() != 2 {
        return None;
    }
    let (y, m, d): (i64, u32, u32) = (y.parse().ok()?, m.parse().ok()?, d.parse().ok()?);
    if !(1970..=9999).contains(&y) || !(1..=12).contains(&m) || d < 1 || d > days_in(y, m) {
        return None;
    }
    let mut secs = 0u64;
    if let Some(c) = clock {
        let parts: Vec<&str> = c.split(':').collect();
        if !(2..=3).contains(&parts.len()) || parts.iter().any(|p| p.len() != 2) {
            return None;
        }
        let h: u64 = parts[0].parse().ok()?;
        let mi: u64 = parts[1].parse().ok()?;
        let se: u64 = if parts.len() == 3 { parts[2].parse().ok()? } else { 0 };
        if h > 23 || mi > 59 || se > 59 {
            return None;
        }
        secs = h * 3600 + mi * 60 + se;
    }
    Some(days_from_civil(y, m, d) as u64 * 86_400 + secs)
}

/// The CAL spelling of a unix time: a date when it is midnight UTC, else a full UTC time.
pub fn fmt_time(t: u64) -> String {
    let (y, m, d) = civil_from_days((t / 86_400) as i64);
    let s = t % 86_400;
    if !(1970..=9999).contains(&y) {
        return format!("@{t}");
    }
    if s == 0 {
        format!("{y:04}-{m:02}-{d:02}")
    } else if s % 60 == 0 {
        format!("{y:04}-{m:02}-{d:02}T{:02}:{:02}Z", s / 3600, s % 3600 / 60)
    } else {
        format!("{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z", s / 3600, s % 3600 / 60, s % 60)
    }
}

/// Plain-English UTC time: `2027-01-22 08:00:00 UTC`.
pub fn say_time(t: u64) -> String {
    let (y, m, d) = civil_from_days((t / 86_400) as i64);
    let s = t % 86_400;
    format!("{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02} UTC", s / 3600, s % 3600 / 60, s % 60)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn amounts() {
        assert_eq!(amount("10MB"), Some(10_000_000));
        assert_eq!(amount("1_000"), Some(1000));
        assert_eq!(amount("1MiB"), Some(1 << 20));
        assert_eq!(duration("10m"), Some(600));
        assert_eq!(duration("10MB"), None);
        assert_eq!(bytes("1h"), None);
        assert_eq!(amount("MB"), None);
        assert_eq!(amount("10 MB"), None);
        assert_eq!(fmt_bytes(500_000_000), "500MB");
        assert_eq!(fmt_bytes(26), "26B");
        assert_eq!(fmt_duration(3600), "1h");
        assert_eq!(fmt_duration(90), "90s");
    }

    #[test]
    fn times() {
        assert_eq!(time("1970-01-01"), Some(0));
        assert_eq!(time("2027-01-15T08:00:00Z"), Some(1_800_000_000));
        assert_eq!(time("2027-01-15T08:00Z"), Some(1_800_000_000));
        assert_eq!(time("@1800000000"), Some(1_800_000_000));
        assert_eq!(time("2026-02-29"), None);
        assert_eq!(time("2028-02-29"), Some(days_from_civil(2028, 2, 29) as u64 * 86400));
        assert_eq!(fmt_time(1_800_000_000), "2027-01-15T08:00Z");
        assert_eq!(fmt_time(time("2026-12-01").unwrap()), "2026-12-01");
        for t in [0, 1, 59, 1_800_000_000, 1_800_000_061, 4_102_444_800] {
            assert_eq!(time(&fmt_time(t)), Some(t), "{t}");
        }
        assert_eq!(say_time(1_800_000_000), "2027-01-15 08:00:00 UTC");
    }
}
