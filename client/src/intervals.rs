/// Trait defining a type containing range data.
pub trait RangeData {
    fn start(&self) -> u64;
    fn end(&self) -> u64;
}

/// Errors that may occur when reading a subscriber address from the server.
#[derive(Debug, thiserror::Error)]
pub enum AddIntervalError {
    /// Error returned when the new interval overlaps with any existing intervals.
    #[error("Interval overlaps with existing intervals")]
    OverlappingIntervals,

    /// Error returned when the new interval is out of bounds.
    #[error("Interval is out of bounds: {0}")]
    OutOfBounds(u64),

    /// Error returned when the new interval has a size of zero.
    /// Returns the interval start and end values given.
    #[error("Interval has a size of zero: {0}-{1}")]
    ZeroSize(u64, u64),
}

/// Helper for managing file intervals.
pub struct FileIntervals<R: RangeData> {
    intervals: Vec<R>,
    total_size: u64,
}
impl<R: RangeData> FileIntervals<R> {
    /// Create a new multi-download progress tracker.
    #[must_use]
    pub fn new(total_size: u64) -> Self {
        Self {
            intervals: Vec::new(),
            total_size,
        }
    }

    /// Add a new interval to track.
    /// # Errors
    /// Returns an error if:
    /// * the new interval overlaps with any existing intervals
    /// * the new interval is out of bounds
    /// * the new interval has a size of zero
    /// The state is not modified on error.
    pub fn add_interval(&mut self, range: R) -> Result<(), AddIntervalError> {
        let range_start = range.start();
        let range_end = range.end();
        if range_start >= range_end {
            return Err(AddIntervalError::ZeroSize(range_start, range_end));
        }
        if range_end > self.total_size {
            return Err(AddIntervalError::OutOfBounds(range_end));
        }

        let Err(i) = self
            .intervals
            .binary_search_by(|r| r.start().cmp(&range_start))
        else {
            return Err(AddIntervalError::OverlappingIntervals);
        };

        if (i > 0 && self.intervals[i - 1].end() > range_start)
            || (i < self.intervals.len() && range_end > self.intervals[i].start())
        {
            return Err(AddIntervalError::OverlappingIntervals);
        }

        self.intervals.insert(i, range);
        Ok(())
    }

    /// Get the next empty range available.
    /// Returns `None` if there are no gaps.
    pub fn next_empty_range(&self) -> Option<std::ops::Range<u64>> {
        // Look through intervals for gaps.
        let mut last_end = 0;
        for range in &self.intervals {
            if last_end < range.start() {
                return Some(last_end..range.start());
            }
            last_end = range.end();
        }

        // Check for a gap at the end.
        if last_end < self.total_size {
            return Some(last_end..self.total_size);
        }
        None
    }

    /// Get the total file size.
    #[must_use]
    pub fn total_size(&self) -> u64 {
        self.total_size
    }
}
