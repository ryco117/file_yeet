/// Maximum recommended download interval chunk size in bytes.
pub const DOWNLOAD_CHUNK_INTERVAL_MAX: u64 = 256 * 1024 * 1024;

/// Minimum recommended interval chunk size in bytes.
/// The actual minimum should always be the remaining size if it is smaller than this.
pub const DOWNLOAD_CHUNK_INTERVAL_MIN: u64 = 64 * 1024;

/// Trait defining a type containing range data.
pub trait RangeData {
    fn start(&self) -> u64;
    fn end(&self) -> u64;
}
impl RangeData for std::ops::Range<u64> {
    fn start(&self) -> u64 {
        self.start
    }
    fn end(&self) -> u64 {
        self.end
    }
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
#[derive(Clone, Debug)]
pub struct FileIntervals<R: RangeData> {
    intervals: Vec<R>,
    total_size: u64,
    remaining_size: u64,
}
impl<R: RangeData> FileIntervals<R> {
    /// Create a new multi-download progress tracker.
    #[must_use]
    pub fn new(total_size: u64) -> Self {
        Self {
            intervals: Vec::new(),
            total_size,
            remaining_size: total_size,
        }
    }

    /// Add a new interval to track.
    /// # Errors
    /// Returns an error if:
    /// * the new interval has a size of zero
    /// * the new interval overlaps with any existing intervals
    /// * the new interval is out of bounds
    ///
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

        let Err(i) = self.intervals.binary_search_by_key(&range_start, R::start) else {
            return Err(AddIntervalError::OverlappingIntervals);
        };

        if (i > 0 && self.intervals[i - 1].end() > range_start)
            || (i < self.intervals.len() && range_end > self.intervals[i].start())
        {
            return Err(AddIntervalError::OverlappingIntervals);
        }

        self.intervals.insert(i, range);
        self.remaining_size -= range_end - range_start;
        Ok(())
    }

    /// Remove the interval with the given range start.
    /// Returns the removed interval, or `None` if the interval was not found.
    pub fn remove_interval_at(&mut self, range_start: u64) -> Option<R> {
        let index = self
            .intervals
            .binary_search_by_key(&range_start, RangeData::start)
            .ok()?;

        let range = self.intervals.remove(index);
        self.remaining_size += range.end() - range.start();
        Some(range)
    }

    /// Get a mutable reference to the interval with the given range start.
    /// Returns `None` if the interval was not found.
    /// # Safety
    /// Changing the start or end of the interval may invalidate the internal state of the `FileIntervals`.
    /// Use with caution.
    pub fn interval_at_mut(&mut self, range_start: u64) -> Option<&mut R> {
        let index = self
            .intervals
            .binary_search_by_key(&range_start, RangeData::start)
            .ok()?;

        self.intervals.get_mut(index)
    }

    /// Get the next empty range available.
    /// Returns `None` if there are no gaps.
    #[must_use]
    pub fn next_empty_range(&self) -> Option<std::ops::Range<u64>> {
        if self.remaining_size == 0 {
            return None;
        }

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

        tracing::error!("FileIntervals::next_empty_range: remaining_size > 0 but no gaps found");
        None
    }

    /// Get the next download chunk range. Prefers to take the maximum chunk size, `DOWNLOAD_CHUNK_INTERVAL_MAX`.
    /// Returns `None` if there are no gaps.
    #[must_use]
    pub fn next_download_chunk(&self) -> Option<std::ops::Range<u64>> {
        let empty_range = self.next_empty_range()?;
        let chunk_end = empty_range
            .end
            .min(empty_range.start + DOWNLOAD_CHUNK_INTERVAL_MAX);
        Some(empty_range.start..chunk_end)
    }

    /// Convert the ranges to another type. Filters out zero-size ranges (after conversion) without error.
    /// # Errors
    /// Returns an error if adding any of the converted ranges fails.
    pub fn convert_ranges<S, F>(self, f: F) -> Result<FileIntervals<S>, AddIntervalError>
    where
        S: RangeData,
        F: Fn(R) -> S,
    {
        let Self {
            intervals,
            total_size,
            ..
        } = self;

        // Map the intervals to the new type.
        let mut new_intervals = FileIntervals::new(total_size);
        for range in intervals.into_iter().map(f) {
            match new_intervals.add_interval(range) {
                Ok(()) | Err(AddIntervalError::ZeroSize(_, _)) => {}
                Err(e) => return Err(e),
            }
        }

        // TODO: Allow for a merge function to optionally combine adjacent intervals.
        //       This would reduce disk usage when saving completed intervals for a partial
        //       download. Currently, all non-empty intervals are saved/retained, even if they can
        //       be more optimally represented as a single interval.

        Ok(new_intervals)
    }

    /// Extract the ranges as a vector, consuming `self`.
    #[must_use]
    pub fn into_ranges(self) -> Vec<R> {
        self.intervals
    }

    /// Get the intervals being managed.
    #[must_use]
    pub fn ranges(&self) -> &[R] {
        &self.intervals
    }
}
