use crate::Error;

#[cfg(not(target_arch = "wasm32"))]
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(target_arch = "wasm32")]
use instant::SystemTime;

#[cfg(target_arch = "wasm32")]
const UNIX_EPOCH: SystemTime = SystemTime::UNIX_EPOCH;

/// A timestamp is a value that represents the number of milliseconds
/// elapsed since the UNIX EPOCH (including leap seconds!). While stored
/// in a u64, it serializes to 47 bits and thus must be <= `0x7FFF_FFFF_FFFF`.
// NOTE: This must have a maximum of 47 bits, with the 48 bit zeroed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Timestamp(u64);

impl Timestamp {
    /// This creates a timestamp from a number of milliseconds from the `UNIX_EPOCH`.
    ///
    /// If the parameter is larger than the maximum 47-bit value,
    /// it will return None.
    #[must_use]
    pub fn from_millis(millis: u64) -> Option<Timestamp> {
        if millis > 0x7FFF_FFFF_FFFF {
            None
        } else {
            Some(Timestamp(millis))
        }
    }

    /// As milliseconds from the `UNIX_EPOCH`
    #[must_use]
    pub fn as_millis(&self) -> u64 {
        self.0
    }

    /// Create a Timestamp from unixtime
    ///
    /// # Errors
    ///
    /// Returns an `Err` if microseconds is >= 1000, if the time is beyond the leapsecond
    /// expiry date, or the resultant timestamp is numerically out of valid range.
    pub fn from_unixtime(seconds: u64, microseconds: u64) -> Result<Timestamp, Error> {
        if microseconds >= 1000 {
            return Err(Error::TimeOutOfRange);
        }
        if seconds > LEAP_SECONDS_EXPIRE {
            return Err(Error::TimeIsBeyondLeapSecondData);
        }

        let leaps = iana_ntp_leap_seconds()
            .iter()
            .map(|ntp| ntp - 2_208_988_800)
            .filter(|x| *x < seconds)
            .count() as u64;

        let millis: u64 = seconds
            .checked_add(leaps)
            .ok_or(Error::TimeOutOfRange)?
            .checked_mul(1000)
            .ok_or(Error::TimeOutOfRange)?
            .checked_add(microseconds)
            .ok_or(Error::TimeOutOfRange)?;

        if millis > 0x7FFF_FFFF_FFFF {
            Err(Error::TimeOutOfRange)
        } else {
            Ok(Timestamp(millis))
        }
    }

    /// Converts to unixtime seconds and milliseconds
    #[must_use]
    pub fn to_unixtime(&self) -> (u64, u64) {
        let unadjusted_secs = self.0 / 1000;
        let microsecs = self.0 % 1000;

        let leaps = iana_ntp_leap_seconds()
            .iter()
            .enumerate()
            .map(|(i, ntp)| ntp - 2_208_988_800 + 1 + i as u64)
            .filter(|x| *x < unadjusted_secs)
            .count() as u64;

        (unadjusted_secs - leaps, microsecs)
    }

    /// Get the current time
    ///
    /// # Errors
    ///
    /// Returns an error if the current time is before the `UNIX_EPOCH`
    pub fn now() -> Result<Timestamp, Error> {
        let duration = SystemTime::now().duration_since(UNIX_EPOCH)?;

        Self::from_unixtime(duration.as_secs(), u64::from(duration.subsec_millis()))
    }

    /// View as a 6-byte little-endian slice
    #[allow(clippy::missing_panics_doc)]
    #[must_use]
    pub fn to_slice(&self) -> [u8; 6] {
        <[u8; 6]>::try_from(&self.0.to_le_bytes()[..6]).unwrap()
    }

    /// Create from a 6-byte little-endian slice
    ///
    /// # Errors
    ///
    /// Returns an error if the data is out o frange for a `Timestamp`
    pub fn from_slice(slice: &[u8; 6]) -> Result<Timestamp, Error> {
        let mut eight: [u8; 8] = [0; 8];
        eight[..6].copy_from_slice(slice);
        let millis: u64 = u64::from_le_bytes(eight);

        if millis > 0x7FFF_FFFF_FFFF {
            Err(Error::TimeOutOfRange)
        } else {
            Ok(Timestamp(millis))
        }
    }
}

// https://data.iana.org/time-zones/data/leap-seconds.list
//
// Expires 28 June 2025
const LEAP_SECONDS_EXPIRE: u64 = 1_751_068_800; // unixtime
                                                //
#[allow(clippy::unreadable_literal)]
fn iana_ntp_leap_seconds() -> Vec<u64> {
    vec![
        // Unixtime
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

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_timestamp() {
        // Test a date in 1986 (14 leap seconds elapsed)
        let timestamp = Timestamp::from_unixtime(500000000, 987).unwrap();
        assert_eq!(timestamp.as_millis(), 500000014987);

        // Test a date in 2024 (28 leap seconds elapsed)
        let timestamp = Timestamp::from_unixtime(1732950200, 1).unwrap();
        assert_eq!(timestamp.as_millis(), 1732950228001);

        // convert to and from a slice and compare
        let slice = timestamp.to_slice();
        let timestamp2 = Timestamp::from_slice(&slice).unwrap();
        assert_eq!(timestamp, timestamp2);
    }

    #[test]
    fn test_timestamp_unixtime_conversions() {
        // Trial 10 seconds before and after the 4th leapsecond
        for u in 126230400 - 10..126230400 + 10 {
            let ts = Timestamp::from_unixtime(u, 500).unwrap();
            println!("{:?}", ts); // so you can see the leap
            let (u2, _) = ts.to_unixtime();
            assert_eq!(u, u2);
        }
    }
}
