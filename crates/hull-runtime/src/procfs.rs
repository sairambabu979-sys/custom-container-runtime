//! Reading process information from `/proc`.

use std::io;

/// The fields of `/proc/<pid>/stat` that hull uses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProcStat {
    /// Process state: `R`, `S`, `D`, `Z` (zombie), `T`, ...
    pub state: char,
    /// Start time in clock ticks after boot. Together with the PID, this identifies a process
    /// uniquely: a recycled PID has a different start time.
    pub start_time: u64,
}

impl ProcStat {
    /// Read `/proc/<pid>/stat`.
    pub fn read(pid: i32) -> io::Result<Self> {
        let text = std::fs::read_to_string(format!("/proc/{pid}/stat"))?;
        Self::parse(&text).ok_or_else(|| io::Error::other(format!("malformed /proc/{pid}/stat")))
    }

    /// Parse the contents of a `stat` file.
    ///
    /// The second field is the command name in parentheses, and the command name may itself
    /// contain spaces and `)`. Splitting the whole line on whitespace is therefore wrong. The only
    /// robust approach is to find the *last* `)` and count fields from there.
    pub fn parse(text: &str) -> Option<Self> {
        let after_comm = &text[text.rfind(')')? + 1..];
        let mut fields = after_comm.split_whitespace();
        let state = fields.next()?.chars().next()?;
        // `state` is field 3; `starttime` is field 22, i.e. 18 fields further.
        let start_time = fields.nth(18)?.parse().ok()?;
        Some(Self { state, start_time })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LINE: &str = "1234 (evil) name) x) S 1 1234 1234 0 -1 4194560 100 0 0 0 1 2 0 0 20 0 1 0 987654 1000 200 18446744073709551615";

    #[test]
    fn parses_hostile_command_names() {
        let stat = ProcStat::parse(LINE).unwrap();
        assert_eq!(stat.state, 'S');
        assert_eq!(stat.start_time, 987_654);
    }

    #[test]
    fn reads_own_process() {
        let stat = ProcStat::read(std::process::id().try_into().unwrap()).unwrap();
        // /proc/<pid>/stat describes the *main* thread, which may be asleep while the test harness
        // runs this test on a worker thread.
        assert!(matches!(stat.state, 'R' | 'S'), "state {:?}", stat.state);
        assert!(stat.start_time > 0);
    }

    #[test]
    fn rejects_truncated_input() {
        assert_eq!(ProcStat::parse("1 (x) S 1 2"), None);
        assert_eq!(ProcStat::parse("no parens"), None);
    }
}
