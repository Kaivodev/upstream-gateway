//! Gregorian civil dates and Unix seconds, including dates before the epoch.
pub type Timestamp = (i64, u32);
pub fn valid((s, n): Timestamp) -> bool {
    (-62135596800..=253402300799).contains(&s) && n < 1_000_000_000
}
fn days(y: i64, m: i64, d: i64) -> i64 {
    let y = y - i64::from(m <= 2);
    let era = y.div_euclid(400);
    let year = y - era * 400;
    era * 146097 + year * 365 + year / 4 - year / 100
        + (153 * (m + if m > 2 { -3 } else { 9 }) + 2) / 5
        + d
        - 1
        - 719468
}
pub fn parse(raw: &str) -> Option<Timestamp> {
    let b = raw.as_bytes();
    if !raw.is_ascii()
        || b.len() < 20
        || b[4] != b'-'
        || b[7] != b'-'
        || b[10] != b'T'
        || b[13] != b':'
        || b[16] != b':'
    {
        return None;
    }
    let num = |a: usize, n: usize| {
        let s = raw.get(a..a + n)?;
        s.bytes()
            .all(|b| b.is_ascii_digit())
            .then(|| s.parse::<i64>().ok())
            .flatten()
    };
    let (y, m, d, h, min, s) = (
        num(0, 4)?,
        num(5, 2)?,
        num(8, 2)?,
        num(11, 2)?,
        num(14, 2)?,
        num(17, 2)?,
    );
    let max = match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => 28 + i64::from(y % 4 == 0 && (y % 100 != 0 || y % 400 == 0)),
        _ => return None,
    };
    if y == 0 || d < 1 || d > max || h >= 24 || min >= 60 || s >= 60 {
        return None;
    }
    let mut i = 19;
    let mut ns = 0;
    if b[i] == b'.' {
        i += 1;
        let start = i;
        while b.get(i).is_some_and(u8::is_ascii_digit) {
            i += 1
        }
        let n = i - start;
        if !(1..=9).contains(&n) {
            return None;
        }
        ns = (num(start, n)? as u32) * 10u32.pow((9 - n) as u32);
    }
    let offset = match &b[i..] {
        b"Z" => 0,
        [sign @ (b'+' | b'-'), _, _, b':', _, _] => {
            let h = num(i + 1, 2)?;
            let m = num(i + 4, 2)?;
            if h >= 24 || m >= 60 {
                return None;
            }
            (h * 3600 + m * 60) * if *sign == b'+' { 1 } else { -1 }
        }
        _ => return None,
    };
    let t = (days(y, m, d) * 86400 + h * 3600 + min * 60 + s - offset, ns);
    valid(t).then_some(t)
}
pub fn format(t: Timestamp) -> Option<String> {
    if !valid(t) {
        return None;
    }
    let (s, ns) = t;
    let z = s.div_euclid(86400) + 719468;
    let era = z.div_euclid(146097);
    let day = z - era * 146097;
    let year = (day - day / 1460 + day / 36524 - day / 146096) / 365;
    let doy = day - (365 * year + year / 4 - year / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = mp + if mp < 10 { 3 } else { -9 };
    let y = year + era * 400 + i64::from(m <= 2);
    let h = s.rem_euclid(86400) / 3600;
    let min = s.rem_euclid(3600) / 60;
    let sec = s.rem_euclid(60);
    let frac = if ns == 0 {
        String::new()
    } else {
        format!(".{ns:09}").trim_end_matches('0').to_owned()
    };
    Some(format!(
        "{y:04}-{m:02}-{d:02}T{h:02}:{min:02}:{sec:02}{frac}Z"
    ))
}
