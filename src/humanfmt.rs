//! SI-decimal `Display` adapters for the byte counts, transfer rates and
//! durations that appear in log lines and the web interface.
//!
//! Three shapes, one set of rules. Units are decimal (kB = 1000 B, not 1024),
//! matching what apt and the mirrors report. A unit is promoted at
//! `NEXT_UNIT` (999.5) rather than at 1000, so the zero-decimal rendering can
//! never read `1000kB`. The decimal count shrinks as the mantissa grows: two
//! digits below 10, one below 100, none above.
//!
//! [`HumanFmt::Rate`] divides by its window and renders `???B/s` for a
//! zero-length one - see `precise_instant` for why the std clock makes that
//! nearly unreachable, and `docs/logging.md` for why it is the formatter's own
//! output rather than the "unknown value" placeholder.
//! [`HumanFmt::Time`] leaves the scaled-unit ladder at 600 s and switches to a
//! `1d 2h 3m 4s` breakdown, omitting every zero component.

#[must_use]
pub(crate) enum HumanFmt {
    Size(u64),
    Rate(u64, std::time::Duration),
    Time(std::time::Duration),
}

impl std::fmt::Display for HumanFmt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        #[inline]
        #[must_use]
        const fn precision(size: f64) -> usize {
            if size > 100.0 {
                0
            } else if size > 10.0 {
                1
            } else {
                2
            }
        }

        const NEXT_UNIT: f64 = 999.5;

        #[expect(clippy::cast_precision_loss, reason = "only used for display purposes")]
        match *self {
            Self::Size(bytes) => {
                if bytes < 1000 {
                    return write!(f, "{bytes}B");
                }
                let size = bytes as f64 / 1000.0;
                if size < NEXT_UNIT {
                    return write!(f, "{size:.0$}kB", precision(size));
                }
                let size = size / 1000.0;
                if size < NEXT_UNIT {
                    return write!(f, "{size:.0$}MB", precision(size));
                }
                let size = size / 1000.0;
                if size < NEXT_UNIT {
                    return write!(f, "{size:.0$}GB", precision(size));
                }
                let size = size / 1000.0;
                write!(f, "{size:.0$}TB", precision(size))
            }
            Self::Rate(bytes, time) => {
                let time = time.as_secs_f64();
                if time == 0.0 {
                    return write!(f, "???B/s");
                }
                let rate = bytes as f64 / time;
                if rate < NEXT_UNIT {
                    return write!(f, "{rate:.0$}B/s", precision(rate));
                }
                let rate = rate / 1000.0;
                if rate < NEXT_UNIT {
                    return write!(f, "{rate:.0$}kB/s", precision(rate));
                }
                let rate = rate / 1000.0;
                if rate < NEXT_UNIT {
                    return write!(f, "{rate:.0$}MB/s", precision(rate));
                }
                let rate = rate / 1000.0;
                if rate < NEXT_UNIT {
                    return write!(f, "{rate:.0$}GB/s", precision(rate));
                }
                let rate = rate / 1000.0;
                write!(f, "{rate:.0$}TB/s", precision(rate))
            }
            Self::Time(time) => {
                let time = time.as_nanos();
                if time < 1000 {
                    return write!(f, "{time}ns");
                }

                let time = time as f64 / 1000.0;
                if time < NEXT_UNIT {
                    return write!(f, "{time:.0$}us", precision(time));
                }

                let time = time / 1000.0;
                if time < NEXT_UNIT {
                    return write!(f, "{time:.0$}ms", precision(time));
                }

                let time = time / 1000.0;
                if time < 600.0 {
                    return write!(f, "{time:.0$}s", precision(time));
                }

                #[expect(
                    clippy::cast_possible_truncation,
                    clippy::cast_sign_loss,
                    reason = "only used for display purposes"
                )]
                let time = time as u64;

                let secs = time % 60;
                let time = time / 60;
                let mins = time % 60;
                let time = time / 60;
                let hours = time % 24;
                let time = time / 24;
                let days = time;

                let days_fmt = if days != 0 {
                    format_args!("{days}d")
                } else {
                    format_args!("")
                };

                let hours_fmt = if hours != 0 {
                    format_args!("{}{hours}h", if days == 0 { "" } else { " " })
                } else {
                    format_args!("")
                };

                let mins_fmt = if mins != 0 {
                    format_args!("{}{mins}m", if hours == 0 && days == 0 { "" } else { " " })
                } else {
                    format_args!("")
                };

                let secs_fmt = if secs != 0 {
                    format_args!(
                        "{}{secs}s",
                        if mins == 0 && hours == 0 && days == 0 {
                            ""
                        } else {
                            " "
                        }
                    )
                } else {
                    format_args!("")
                };

                write!(f, "{days_fmt}{hours_fmt}{mins_fmt}{secs_fmt}")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use crate::humanfmt::HumanFmt;

    #[test]
    fn size_test() {
        assert_eq!(format!("{}", HumanFmt::Size(0)), "0B");
        assert_eq!(format!("{}", HumanFmt::Size(900)), "900B");
        assert_eq!(format!("{}", HumanFmt::Size(1024)), "1.02kB");
        assert_eq!(format!("{}", HumanFmt::Size(24756)), "24.8kB");
        assert_eq!(format!("{}", HumanFmt::Size(247_569_325_892)), "248GB");
        assert_eq!(format!("{}", HumanFmt::Size(u64::MAX)), "18446744TB");
    }

    #[test]
    fn size_unit_boundary_promotes_instead_of_rounding_to_1000() {
        // Just below the promotion threshold: still the smaller unit.
        assert_eq!(format!("{}", HumanFmt::Size(999_499)), "999kB");
        // From here the zero-decimal rendering would read `1000kB`.
        assert_eq!(format!("{}", HumanFmt::Size(999_500)), "1.00MB");
        assert_eq!(format!("{}", HumanFmt::Size(999_999)), "1.00MB");
        assert_eq!(format!("{}", HumanFmt::Size(1_000_000)), "1.00MB");
        assert_eq!(format!("{}", HumanFmt::Size(999_999_999)), "1.00GB");
        assert_eq!(format!("{}", HumanFmt::Size(999_999_999_999)), "1.00TB");
    }

    #[test]
    fn rate_test() {
        // Zero window is unmeasurable -> sentinel (essentially unreachable with
        // the std::time::Instant ns clock, but guards against a 0/0 divide).
        assert_eq!(
            format!("{}", HumanFmt::Rate(0, Duration::from_millis(0))),
            "???B/s"
        );
        assert_eq!(
            format!("{}", HumanFmt::Rate(1000, Duration::from_millis(0))),
            "???B/s"
        );
        assert_eq!(
            format!("{}", HumanFmt::Rate(0, Duration::from_secs(1))),
            "0.00B/s"
        );
        assert_eq!(
            format!("{}", HumanFmt::Rate(1, Duration::from_secs(1_000_000))),
            "0.00B/s"
        );
        assert_eq!(
            format!("{}", HumanFmt::Rate(1000, Duration::from_secs(1))),
            "1.00kB/s"
        );
        // Sub-millisecond host-local window stays finite.
        assert_eq!(
            format!("{}", HumanFmt::Rate(61_700, Duration::from_micros(50))),
            "1.23GB/s"
        );
        assert_eq!(
            format!(
                "{}",
                HumanFmt::Rate(u64::MAX, Duration::from_secs(1_000_000))
            ),
            "18.4TB/s"
        );
    }

    #[test]
    fn time_test() {
        assert_eq!(
            format!("{}", HumanFmt::Time(Duration::from_nanos(0))),
            "0ns"
        );
        assert_eq!(
            format!("{}", HumanFmt::Time(Duration::from_nanos(900))),
            "900ns"
        );
        assert_eq!(
            format!("{}", HumanFmt::Time(Duration::from_nanos(1024))),
            "1.02us"
        );
        assert_eq!(
            format!("{}", HumanFmt::Time(Duration::from_nanos(24756))),
            "24.8us"
        );
        assert_eq!(
            format!("{}", HumanFmt::Time(Duration::from_nanos(247_569_325_892))),
            "248s"
        );
        assert_eq!(
            format!("{}", HumanFmt::Time(Duration::from_secs(601))),
            "10m 1s"
        );
        assert_eq!(
            format!("{}", HumanFmt::Time(Duration::from_secs(86401))),
            "1d 1s"
        );
        assert_eq!(
            format!("{}", HumanFmt::Time(Duration::from_mins(1441))),
            "1d 1m"
        );
        assert_eq!(
            format!("{}", HumanFmt::Time(Duration::from_nanos(u64::MAX))),
            "213503d 23h 34m 33s"
        );
    }

    #[test]
    fn time_and_rate_unit_boundaries_promote() {
        // Would render as `1000us` / `1000ms` without the promotion threshold.
        assert_eq!(
            format!("{}", HumanFmt::Time(Duration::from_nanos(999_999))),
            "1.00ms"
        );
        assert_eq!(
            format!("{}", HumanFmt::Time(Duration::from_nanos(999_499))),
            "999us"
        );
        assert_eq!(
            format!("{}", HumanFmt::Time(Duration::from_nanos(999_999_999))),
            "1.00s"
        );
        assert_eq!(
            format!("{}", HumanFmt::Rate(999_999, Duration::from_secs(1))),
            "1.00MB/s"
        );
        assert_eq!(
            format!("{}", HumanFmt::Rate(999_499, Duration::from_secs(1))),
            "999kB/s"
        );
    }
}
