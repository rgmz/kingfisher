use core::ops::Range;
use std::cell::RefCell;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// A point defined by a byte offset.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Copy, Clone)]
pub struct OffsetPoint(pub usize);

impl OffsetPoint {
    #[inline]
    pub fn new(idx: usize) -> Self {
        OffsetPoint(idx)
    }
}

/// A non‑empty span defined by two byte offsets (half‑open interval `[start, end)`).
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct OffsetSpan {
    pub start: usize,
    pub end: usize,
}

impl std::fmt::Display for OffsetSpan {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}-{}", self.start, self.end)
    }
}

impl OffsetSpan {
    #[inline]
    pub fn from_offsets(start: OffsetPoint, end: OffsetPoint) -> Self {
        OffsetSpan { start: start.0, end: end.0 }
    }

    #[inline]
    pub fn from_range(range: Range<usize>) -> Self {
        OffsetSpan { start: range.start, end: range.end }
    }

    /// Length in bytes.
    #[inline]
    #[must_use]
    pub fn len(&self) -> usize {
        self.end.saturating_sub(self.start)
    }

    /// True if empty or inverted.
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.start >= self.end
    }

    /// True if `other` lies entirely within `self`.
    #[inline]
    #[must_use]
    pub fn fully_contains(&self, other: &Self) -> bool {
        self.start <= other.start && other.end <= self.end
    }
}

/// A point in the source file (line 1‑indexed, column 0‑indexed).
#[derive(Debug, PartialEq, Eq, Hash, Copy, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SourcePoint {
    pub line: usize,
    pub column: usize,
}

impl std::fmt::Display for SourcePoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.line, self.column)
    }
}

/// A closed interval between two source points.
#[derive(Debug, PartialEq, Eq, Hash, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SourceSpan {
    pub start: SourcePoint,
    pub end: SourcePoint,
}

impl std::fmt::Display for SourceSpan {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}-{}", self.start, self.end)
    }
}

/// Records newline byte‑offsets to map offsets -- (line, column).
pub struct LocationMapping<'a> {
    bytes: &'a [u8],
    newline_offsets: RefCell<Vec<usize>>,
}

impl<'a> LocationMapping<'a> {
    /// Create a new mapping without pre-scanning the entire input.
    pub fn new(input: &'a [u8]) -> Self {
        LocationMapping { bytes: input, newline_offsets: RefCell::new(Vec::new()) }
    }

    fn ensure_offsets_up_to(&self, offset: usize) {
        let mut offsets = self.newline_offsets.borrow_mut();
        let start = offsets.last().map_or(0, |&last| last + 1);
        if offset < start {
            return;
        }
        let end = offset.min(self.bytes.len());
        for nl in memchr::memchr_iter(b'\n', &self.bytes[start..end]) {
            offsets.push(start + nl);
        }
    }

    fn source_point_from_offsets(offsets: &[usize], offset: usize) -> SourcePoint {
        let line = match offsets.binary_search(&offset) {
            Ok(idx) => idx + 2,
            Err(idx) => idx + 1,
        };
        let column = if let Some(&last) = offsets.get(line.saturating_sub(2)) {
            offset.saturating_sub(last + 1)
        } else {
            offset
        };
        SourcePoint { line, column }
    }

    /// Map a byte offset to a `SourcePoint`.
    pub fn get_source_point(&self, offset: usize) -> SourcePoint {
        self.ensure_offsets_up_to(offset);
        let offsets = self.newline_offsets.borrow();
        Self::source_point_from_offsets(&offsets, offset)
    }

    /// Map an `OffsetSpan` -- `SourceSpan` (closed interval).
    pub fn get_source_span(&self, span: &OffsetSpan) -> SourceSpan {
        self.ensure_offsets_up_to(span.end.saturating_sub(1));
        let offsets = self.newline_offsets.borrow();
        let start = Self::source_point_from_offsets(&offsets, span.start);
        let end = Self::source_point_from_offsets(&offsets, span.end.saturating_sub(1));
        SourceSpan { start, end }
    }
}

/// Compact representation of a source span to reduce per-match footprint while
/// still being able to materialize full line/column data on demand.
#[derive(Debug, Clone, Copy, Deserialize, Serialize, JsonSchema)]
pub struct CompactSourceSpan {
    pub start_line: u32,
    pub start_column: u32,
    pub end_line: u32,
    pub end_column: u32,
}

impl CompactSourceSpan {
    #[inline]
    fn zero() -> Self {
        Self { start_line: 0, start_column: 0, end_line: 0, end_column: 0 }
    }

    #[inline]
    fn from_source_span(span: &SourceSpan) -> Self {
        Self {
            start_line: span.start.line.try_into().unwrap_or(0),
            start_column: span.start.column.try_into().unwrap_or(0),
            end_line: span.end.line.try_into().unwrap_or(0),
            end_column: span.end.column.try_into().unwrap_or(0),
        }
    }

    #[inline]
    fn to_source_span(self) -> SourceSpan {
        SourceSpan {
            start: SourcePoint {
                line: usize::try_from(self.start_line).unwrap_or(0),
                column: usize::try_from(self.start_column).unwrap_or(0),
            },
            end: SourcePoint {
                line: usize::try_from(self.end_line).unwrap_or(0),
                column: usize::try_from(self.end_column).unwrap_or(0),
            },
        }
    }
}

/// Combined byte‑ and source‑span.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct Location {
    pub offset_span: OffsetSpan,
    #[serde(
        default,
        serialize_with = "serialize_compact_source_span",
        deserialize_with = "deserialize_compact_source_span"
    )]
    #[schemars(with = "SourceSpan")]
    pub source_span: Option<CompactSourceSpan>,
}

impl serde::Serialize for Location {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;

        let mut state = serializer.serialize_struct("Location", 2)?;
        state.serialize_field("offset_span", &self.offset_span)?;
        let source_span = self.source_span().unwrap_or_else(CompactSourceSpan::zero);
        state.serialize_field("source_span", &source_span.to_source_span())?;
        state.end()
    }
}

impl Location {
    #[inline]
    pub fn with_source_span(offset_span: OffsetSpan, source_span: Option<SourceSpan>) -> Self {
        Self {
            offset_span,
            source_span: source_span.as_ref().map(CompactSourceSpan::from_source_span),
        }
    }

    #[inline]
    pub fn source_span(&self) -> Option<CompactSourceSpan> {
        self.source_span
    }

    #[inline]
    pub fn resolved_source_span(&self) -> SourceSpan {
        self.source_span.unwrap_or_else(CompactSourceSpan::zero).to_source_span()
    }
}

fn serialize_compact_source_span<S>(
    span: &Option<CompactSourceSpan>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    let source_span = span.unwrap_or_else(CompactSourceSpan::zero).to_source_span();
    source_span.serialize(serializer)
}

fn deserialize_compact_source_span<'de, D>(
    deserializer: D,
) -> Result<Option<CompactSourceSpan>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let span = SourceSpan::deserialize(deserializer)?;
    Ok(Some(CompactSourceSpan::from_source_span(&span)))
}
