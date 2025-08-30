use crate::{Error, InnerError};
use std::ops::{Add, Sub};
use std::time::Duration;

#[cfg(not(target_arch = "wasm32"))]
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(target_arch = "wasm32")]
use instant::SystemTime;

#[cfg(target_arch = "wasm32")]
const UNIX_EPOCH: SystemTime = SystemTime::UNIX_EPOCH;

/// The largest timestamp (milliseconds).
pub const MAX_NANOSECONDS: i64 = i64::MAX;

/// A timestamp is a value that represents the number of nanoseconds that have
/// elapsed on the surface of the Earth since the UNIX EPOCH (including within
/// leap seconds!).
///
// SAFETY: It must be impossible to create a Timestamp with a negative internal value.
//         the first bit must be 0
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Timestamp(i64);

impl Timestamp {
    /// Timestamp that is all zeroes
    pub const ZERO: Timestamp = Timestamp(0);

    /// Minimum timestamp
    pub const MIN: Timestamp = Timestamp(0);

    /// Minimum timestamp
    pub const MAX: Timestamp = Timestamp(MAX_NANOSECONDS);

    /// This creates a timestamp from a number of nanoseconds from the `UNIX_EPOCH`.
    ///
    /// # Errors
    ///
    /// Return an Err if the input is negative.
    pub fn from_nanoseconds(nanos: i64) -> Result<Timestamp, Error> {
        if nanos < 0 {
            Err(InnerError::TimeOutOfRange.into())
        } else {
            Ok(Timestamp(nanos))
        }
    }

    /// As nanoseconds from the `UNIX_EPOCH`
    #[must_use]
    pub fn as_nanoseconds(&self) -> i64 {
        self.0
    }

    /// Create a Timestamp from unixtime
    ///
    /// # Errors
    ///
    /// Returns an `Err` if `subsec_nanoseconds` is > `999_999_999`, if the time is beyond the
    /// leapsecond expiry date, or the resultant timestamp is numerically out of valid range.
    pub fn from_unixtime(seconds: u64, subsec_nanoseconds: u64) -> Result<Timestamp, Error> {
        if subsec_nanoseconds > 999_999_999 {
            return Err(InnerError::TimeOutOfRange.into());
        }
        if seconds > LEAP_SECONDS_EXPIRE {
            return Err(InnerError::TimeIsBeyondLeapSecondData.into());
        }

        #[allow(clippy::cast_possible_wrap)]
        let leaps = iana_ntp_leap_seconds()
            .iter()
            .map(|ntp| ntp - NTP_TIME_UNIXTIME_OFFSET)
            .filter(|x| *x < seconds)
            .count() as i64;

        #[allow(clippy::cast_possible_wrap)]
        let nanos: i64 = (seconds as i64)
            .checked_add(leaps)
            .ok_or(InnerError::TimeOutOfRange.into_err())?
            .checked_mul(1_000_000_000)
            .ok_or(InnerError::TimeOutOfRange.into_err())?
            .checked_add(subsec_nanoseconds as i64)
            .ok_or(InnerError::TimeOutOfRange.into_err())?;

        Ok(Timestamp(nanos))
    }

    /// Converts to unixtime seconds and `subsec_nanoseconds`
    #[must_use]
    pub fn to_unixtime(&self) -> (u64, u64) {
        #[allow(clippy::cast_sign_loss)]
        let unadjusted_secs = self.0 as u64 / 1_000_000_000;

        #[allow(clippy::cast_sign_loss)]
        let nanosecs = self.0 as u64 % 1_000_000_000;

        let leaps = iana_ntp_leap_seconds()
            .iter()
            .enumerate()
            .map(|(i, ntp)| ntp - NTP_TIME_UNIXTIME_OFFSET + 1 + i as u64)
            .filter(|x| *x < unadjusted_secs)
            .count() as u64;

        (unadjusted_secs - leaps, nanosecs)
    }

    /// Get the current time
    ///
    /// # Errors
    ///
    /// Returns an error if the current time is before the `UNIX_EPOCH` or beyond
    /// the leap second expiry date.
    pub fn now() -> Result<Timestamp, Error> {
        let duration = SystemTime::now().duration_since(UNIX_EPOCH)?;

        Self::from_unixtime(duration.as_secs(), u64::from(duration.subsec_nanos()))
    }

    /// Returns an 8-byte big-endian byte array
    #[allow(clippy::missing_panics_doc)]
    #[must_use]
    pub fn to_bytes(&self) -> [u8; 8] {
        self.0.to_be_bytes()
    }

    /// Create from an 8-byte big-endian slice
    ///
    /// # Errors
    ///
    /// Returns an error if the data is out of range for a `Timestamp`
    pub fn from_bytes(slice: [u8; 8]) -> Result<Timestamp, Error> {
        let n: i64 = i64::from_be_bytes(slice);
        if n < 0 {
            Err(InnerError::TimeOutOfRange.into())
        } else {
            Ok(Timestamp(n))
        }
    }

    /// Create from an 8-byte big-endian slice
    ///
    /// # Safety
    ///
    /// Bytes must be a valid `Timestamp`, otherwise undefined results can occur including
    /// panics
    #[must_use]
    pub unsafe fn from_bytes_unchecked(slice: [u8; 8]) -> Timestamp {
        let n: i64 = i64::from_be_bytes(slice);
        Timestamp(n)
    }

    /// This gives you a sequence of bytes, still in big endian, that
    /// sorts from maximum time to minimum time lexographically.
    #[must_use]
    pub fn to_inverse_bytes(&self) -> [u8; 8] {
        (MAX_NANOSECONDS - self.0).to_be_bytes()
    }

    /// Create from an 8-byte big-endian slice that was created with `to_inverse_bytes()`
    ///
    /// # Errors
    ///
    /// Returns an error if the data is out of range for a `Timestamp`
    pub fn from_inverse_bytes(slice: [u8; 8]) -> Result<Timestamp, Error> {
        let n: i64 = i64::from_be_bytes(slice);
        if n < 0 {
            Err(InnerError::TimeOutOfRange.into())
        } else {
            Ok(Timestamp(MAX_NANOSECONDS - n))
        }
    }
}

// https://data.iana.org/time-zones/data/leap-seconds.list
//
// Expires 28 December 2025
const LEAP_SECONDS_EXPIRE: u64 = 1_766_880_000; // unixtime

const NTP_TIME_UNIXTIME_OFFSET: u64 = 2_208_988_800;

// const EPOCH_2020_IN_UNIXTIME: u64 = 1577836800;

#[allow(clippy::unreadable_literal)]
fn iana_ntp_leap_seconds() -> Vec<u64> {
    vec![
        // NTP Time                           // Unixtime
        2272060800, //	10	# 1 Jan 1972      // 63072000
        2287785600, //	11	# 1 Jul 1972      // 78796800
        2303683200, //	12	# 1 Jan 1973      // 94694400
        2335219200, //	13	# 1 Jan 1974      // 126230400
        2366755200, //	14	# 1 Jan 1975      // 157766400
        2398291200, //	15	# 1 Jan 1976      // 189302400
        2429913600, //	16	# 1 Jan 1977      // 220924800
        2461449600, //	17	# 1 Jan 1978      // 252460800
        2492985600, //	18	# 1 Jan 1979      // 283996800
        2524521600, //	19	# 1 Jan 1980      // 315532800
        2571782400, //	20	# 1 Jul 1981      // 362793600
        2603318400, //	21	# 1 Jul 1982      // 394329600
        2634854400, //	22	# 1 Jul 1983      // 425865600
        2698012800, //	23	# 1 Jul 1985      // 489024000
        2776982400, //	24	# 1 Jan 1988      // 567993600
        2840140800, //	25	# 1 Jan 1990      // 631152000
        2871676800, //	26	# 1 Jan 1991      // 662688000
        2918937600, //	27	# 1 Jul 1992      // 709948800
        2950473600, //	28	# 1 Jul 1993      // 741484800
        2982009600, //	29	# 1 Jul 1994      // 773020800
        3029443200, //	30	# 1 Jan 1996      // 820454400
        3076704000, //	31	# 1 Jul 1997      // 867715200
        3124137600, //	32	# 1 Jan 1999      // 915148800
        3345062400, //	33	# 1 Jan 2006      // 1136073600
        3439756800, //	34	# 1 Jan 2009      // 1230768000
        3550089600, //	35	# 1 Jul 2012      // 1341100800
        3644697600, //	36	# 1 Jul 2015      // 1435708800
        3692217600, //	37	# 1 Jan 2017      // 1483228800
    ]
}

impl std::fmt::Display for Timestamp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Sub for Timestamp {
    type Output = Duration;

    fn sub(self, rhs: Timestamp) -> Self::Output {
        if rhs.0 >= self.0 {
            Duration::ZERO
        } else {
            #[allow(clippy::cast_sign_loss)]
            Duration::from_nanos((self.0 - rhs.0) as u64)
        }
    }
}

impl Sub<Duration> for Timestamp {
    type Output = Timestamp;

    fn sub(self, rhs: Duration) -> Self::Output {
        let rhs_nanos = rhs.as_nanos();
        #[allow(clippy::cast_sign_loss)]
        if rhs_nanos >= (self.0 as u128) {
            Timestamp::MIN
        } else {
            #[allow(clippy::cast_possible_truncation)]
            Timestamp(self.0 - rhs_nanos as i64)
        }
    }
}

impl Add<Duration> for Timestamp {
    type Output = Timestamp;

    fn add(self, rhs: Duration) -> Self::Output {
        let rhs_nanos = rhs.as_nanos();
        #[allow(clippy::cast_sign_loss)]
        if rhs_nanos + (self.0 as u128) > (i64::MAX as u128) {
            Timestamp::MAX
        } else {
            #[allow(clippy::cast_possible_truncation)]
            Timestamp(self.0 + rhs_nanos as i64)
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_timestamp() {
        // Test a date in 1986 (14 leap seconds elapsed)
        let timestamp = Timestamp::from_unixtime(500_000_000, 987_000_000).unwrap();
        assert_eq!(timestamp.as_nanoseconds(), 500_000_014_987_000_000);

        // Test a date in 2024 (28 leap seconds elapsed)
        let timestamp = Timestamp::from_unixtime(1_732_950_200, 100_000_000).unwrap();
        assert_eq!(timestamp.as_nanoseconds(), 1_732_950_228_100_000_000);

        // convert to and from a slice and compare
        let bytes = timestamp.to_bytes();
        let timestamp2 = Timestamp::from_bytes(bytes).unwrap();
        assert_eq!(timestamp, timestamp2);

        // Print now
        println!("NOW={}", Timestamp::now().unwrap());
    }

    #[test]
    fn test_timestamp_unixtime_conversions() {
        // Trial 10 seconds before and after the 4th leapsecond
        for u in 126_230_400 - 10..126_230_400 + 10 {
            let ts = Timestamp::from_unixtime(u, 500_000_000).unwrap();
            println!("{ts:?}"); // so you can see the leap
            let (u2, _) = ts.to_unixtime();
            assert_eq!(u, u2);
        }
    }
}
