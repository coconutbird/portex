//! PE validation framework.
//!
//! This module provides validation for PE structural integrity.
//!
//! # Example
//!
//! ```no_run
//! use portex::PE;
//!
//! let pe = PE::from_file("example.exe").unwrap();
//! let issues = pe.validate();
//!
//! for issue in &issues {
//!     println!("{}: {}", issue.level, issue.message);
//! }
//!
//! if issues.has_errors() {
//!     eprintln!("PE has structural errors!");
//! }
//! ```

use std::fmt;

/// Severity level of a validation issue.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ValidationLevel {
    /// Warning - PE may still be valid but has suspicious characteristics.
    Warning,
    /// Error - PE has structural issues that likely make it invalid.
    Error,
}

impl fmt::Display for ValidationLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ValidationLevel::Warning => write!(f, "Warning"),
            ValidationLevel::Error => write!(f, "Error"),
        }
    }
}

/// Type of validation issue.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ValidationCode {
    /// DOS signature is invalid.
    InvalidDosSignature,
    /// PE signature is invalid.
    InvalidPeSignature,
    /// Optional header magic is invalid.
    InvalidOptionalMagic,
    /// Entry point is outside any section.
    EntryPointOutOfBounds,
    /// Data directory RVA is invalid.
    InvalidDataDirectoryRva,
    /// Sections overlap in file or virtual address space.
    OverlappingSections,
    /// Section RVA/size is invalid.
    InvalidSectionLayout,
    /// Size of image doesn't match calculated value.
    InconsistentImageSize,
    /// Size of headers doesn't match calculated value.
    InconsistentHeadersSize,
    /// Checksum mismatch.
    InvalidChecksum,
    /// File alignment is not a power of 2 or too small.
    InvalidFileAlignment,
    /// Section alignment is not a power of 2 or too small.
    InvalidSectionAlignment,
    /// No sections in PE.
    NoSections,
    /// Section has no data but non-zero raw size.
    EmptySectionWithSize,
}

impl fmt::Display for ValidationCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

/// A single validation issue.
#[derive(Debug, Clone)]
pub struct ValidationIssue {
    /// Severity of the issue.
    pub level: ValidationLevel,
    /// Type of issue.
    pub code: ValidationCode,
    /// Human-readable description.
    pub message: String,
    /// Optional context (e.g., section name, RVA).
    pub context: Option<String>,
}

impl ValidationIssue {
    /// Create a new error.
    pub fn error(code: ValidationCode, message: impl Into<String>) -> Self {
        Self {
            level: ValidationLevel::Error,
            code,
            message: message.into(),
            context: None,
        }
    }

    /// Create a new warning.
    pub fn warning(code: ValidationCode, message: impl Into<String>) -> Self {
        Self {
            level: ValidationLevel::Warning,
            code,
            message: message.into(),
            context: None,
        }
    }

    /// Add context to this issue.
    pub fn with_context(mut self, context: impl Into<String>) -> Self {
        self.context = Some(context.into());
        self
    }

    /// Check if this is an error.
    pub fn is_error(&self) -> bool {
        self.level == ValidationLevel::Error
    }

    /// Check if this is a warning.
    pub fn is_warning(&self) -> bool {
        self.level == ValidationLevel::Warning
    }
}

impl fmt::Display for ValidationIssue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {}: {}", self.level, self.code, self.message)?;
        if let Some(ctx) = &self.context {
            write!(f, " ({})", ctx)?;
        }
        Ok(())
    }
}

/// Collection of validation issues.
#[derive(Debug, Clone, Default)]
pub struct ValidationResult {
    /// All validation issues found.
    pub issues: Vec<ValidationIssue>,
}

impl ValidationResult {
    /// Create an empty result.
    pub fn new() -> Self {
        Self { issues: Vec::new() }
    }

    /// Add an issue.
    pub fn push(&mut self, issue: ValidationIssue) {
        self.issues.push(issue);
    }

    /// Check if there are any errors.
    pub fn has_errors(&self) -> bool {
        self.issues.iter().any(|i| i.is_error())
    }

    /// Check if there are any warnings.
    pub fn has_warnings(&self) -> bool {
        self.issues.iter().any(|i| i.is_warning())
    }

    /// Check if there are no issues.
    pub fn is_ok(&self) -> bool {
        self.issues.is_empty()
    }

    /// Get only errors.
    pub fn errors(&self) -> impl Iterator<Item = &ValidationIssue> {
        self.issues.iter().filter(|i| i.is_error())
    }

    /// Get only warnings.
    pub fn warnings(&self) -> impl Iterator<Item = &ValidationIssue> {
        self.issues.iter().filter(|i| i.is_warning())
    }

    /// Number of issues.
    pub fn len(&self) -> usize {
        self.issues.len()
    }

    /// Check if empty.
    pub fn is_empty(&self) -> bool {
        self.issues.is_empty()
    }

    /// Count of errors.
    pub fn error_count(&self) -> usize {
        self.issues.iter().filter(|i| i.is_error()).count()
    }

    /// Count of warnings.
    pub fn warning_count(&self) -> usize {
        self.issues.iter().filter(|i| i.is_warning()).count()
    }
}

impl IntoIterator for ValidationResult {
    type Item = ValidationIssue;
    type IntoIter = std::vec::IntoIter<ValidationIssue>;

    fn into_iter(self) -> Self::IntoIter {
        self.issues.into_iter()
    }
}

impl<'a> IntoIterator for &'a ValidationResult {
    type Item = &'a ValidationIssue;
    type IntoIter = std::slice::Iter<'a, ValidationIssue>;

    fn into_iter(self) -> Self::IntoIter {
        self.issues.iter()
    }
}
