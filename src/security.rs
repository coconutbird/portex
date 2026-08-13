//! Security directory (Authenticode) parsing.
//!
//! The security directory contains WIN_CERTIFICATE structures for code signing.
//! Unlike other data directories, this one uses a **file offset** (not RVA).
//!
//! # Examples
//!
//! ```no_run
//! use portex::PeFile;
//!
//! # let file_bytes: &[u8] = &[];
//! let pe = PeFile::parse(file_bytes)?;
//!
//! if let Some(certs) = pe.security()? {
//!     for cert in &certs.certificates {
//!         println!("Certificate type: {:?}, revision: {:?}",
//!             cert.certificate_type, cert.revision);
//!         println!("  Data length: {} bytes", cert.data.len());
//!     }
//! }
//! # Ok::<(), portex::Error>(())
//! ```

use crate::prelude::*;
use crate::{Error, Result};

/// WIN_CERTIFICATE revision values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertificateRevision {
    /// WIN_CERT_REVISION_1_0
    Revision1,
    /// WIN_CERT_REVISION_2_0
    Revision2,
    /// Revision not known to this version of the crate.
    Unknown(u16),
}

impl CertificateRevision {
    /// Convert from raw u16.
    pub const fn from_u16(value: u16) -> Self {
        match value {
            0x0100 => Self::Revision1,
            0x0200 => Self::Revision2,
            other => Self::Unknown(other),
        }
    }

    pub const fn as_u16(self) -> u16 {
        match self {
            Self::Revision1 => 0x0100,
            Self::Revision2 => 0x0200,
            Self::Unknown(value) => value,
        }
    }
}

/// WIN_CERTIFICATE type values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertificateType {
    /// WIN_CERT_TYPE_X509 - X.509 certificate
    X509,
    /// WIN_CERT_TYPE_PKCS_SIGNED_DATA - PKCS#7 SignedData
    PkcsSignedData,
    /// WIN_CERT_TYPE_RESERVED_1
    Reserved1,
    /// WIN_CERT_TYPE_TS_STACK_SIGNED - Terminal Server Protocol Stack
    TsStackSigned,
    /// Certificate type not known to this version of the crate.
    Unknown(u16),
}

impl CertificateType {
    /// Convert from raw u16.
    pub const fn from_u16(value: u16) -> Self {
        match value {
            0x0001 => Self::X509,
            0x0002 => Self::PkcsSignedData,
            0x0003 => Self::Reserved1,
            0x0004 => Self::TsStackSigned,
            other => Self::Unknown(other),
        }
    }

    pub const fn as_u16(self) -> u16 {
        match self {
            Self::X509 => 0x0001,
            Self::PkcsSignedData => 0x0002,
            Self::Reserved1 => 0x0003,
            Self::TsStackSigned => 0x0004,
            Self::Unknown(value) => value,
        }
    }
}

/// WIN_CERTIFICATE structure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Certificate {
    /// Total length including the header but excluding alignment padding.
    pub length: u32,
    /// Certificate revision.
    pub revision: CertificateRevision,
    /// Certificate type.
    pub certificate_type: CertificateType,
    /// Raw certificate data (without header).
    pub data: Vec<u8>,
}

impl Certificate {
    /// Minimum header size (length + revision + type).
    pub const HEADER_SIZE: usize = 8;

    /// Parse a single certificate from a byte slice.
    /// Returns the certificate and number of bytes consumed (including padding).
    pub fn parse(data: &[u8]) -> Result<(Self, usize)> {
        if data.len() < Self::HEADER_SIZE {
            return Err(Error::buffer_too_small(Self::HEADER_SIZE, data.len()));
        }

        let length = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize;
        let revision_raw = u16::from_le_bytes([data[4], data[5]]);
        let cert_type_raw = u16::from_le_bytes([data[6], data[7]]);

        if length < Self::HEADER_SIZE || length > data.len() {
            return Err(Error::invalid_data_directory(format!(
                "invalid certificate length: {} (available: {})",
                length,
                data.len()
            )));
        }

        let revision = CertificateRevision::from_u16(revision_raw);

        let certificate_type = CertificateType::from_u16(cert_type_raw);

        let cert_data = data[Self::HEADER_SIZE..length].to_vec();

        // Certificates are 8-byte aligned
        let padded_length = length
            .checked_add(7)
            .map(|value| value & !7)
            .ok_or_else(|| Error::invalid_data_directory("certificate alignment overflow"))?;
        if padded_length > data.len() {
            return Err(Error::invalid_data_directory(format!(
                "aligned certificate length {} exceeds the remaining directory size {}",
                padded_length,
                data.len()
            )));
        }

        Ok((
            Self {
                length: length as u32,
                revision,
                certificate_type,
                data: cert_data,
            },
            padded_length,
        ))
    }
}

/// Security directory containing all certificates.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SecurityDirectory {
    /// List of certificates.
    pub certificates: Vec<Certificate>,
}

impl SecurityDirectory {
    /// Parse all certificates from the security directory data.
    pub fn parse(data: &[u8]) -> Result<Self> {
        let mut certificates = Vec::new();
        let mut offset = 0;

        while offset < data.len() {
            if data.len() - offset < Certificate::HEADER_SIZE {
                return Err(Error::invalid_data_directory(format!(
                    "{} trailing bytes remain after the final certificate",
                    data.len() - offset
                )));
            }

            let (cert, consumed) = Certificate::parse(&data[offset..])?;
            certificates.push(cert);
            offset = offset
                .checked_add(consumed)
                .ok_or_else(|| Error::invalid_data_directory("certificate-table size overflow"))?;
        }

        Ok(Self { certificates })
    }
}

/// Builder for serializing security certificates.
///
/// **Note:** The security directory is special - it uses FILE OFFSETS (not RVAs)
/// and stores certificates in the overlay area after all section data.
/// This builder only creates the certificate data; you must append it to
/// the file manually and update the data directory pointer.
#[derive(Debug, Default)]
pub struct SecurityBuilder;

impl SecurityBuilder {
    /// Create a new builder.
    pub fn new() -> Self {
        Self
    }

    /// Calculate the total size needed for all certificates.
    ///
    /// Each certificate is 8-byte aligned.
    pub fn calculate_size(&self, directory: &SecurityDirectory) -> usize {
        self.try_calculate_size(directory)
            .expect("certificate table size overflow: use try_calculate_size()")
    }

    /// Calculate the table size with checked WIN_CERTIFICATE lengths.
    pub fn try_calculate_size(&self, directory: &SecurityDirectory) -> Result<usize> {
        let size = directory
            .certificates
            .iter()
            .try_fold(0usize, |total, certificate| {
                let length = Certificate::HEADER_SIZE
                    .checked_add(certificate.data.len())
                    .ok_or_else(|| Error::invalid_data_directory("certificate length overflow"))?;
                u32::try_from(length).map_err(|_| {
                    Error::invalid_data_directory("WIN_CERTIFICATE length exceeds u32")
                })?;
                let padded = length
                    .checked_add(7)
                    .map(|value| value & !7)
                    .ok_or_else(|| {
                        Error::invalid_data_directory("certificate alignment overflow")
                    })?;
                total
                    .checked_add(padded)
                    .ok_or_else(|| Error::invalid_data_directory("certificate-table size overflow"))
            })?;
        u32::try_from(size)
            .map_err(|_| Error::invalid_data_directory("certificate table exceeds u32"))?;
        Ok(size)
    }

    /// Build the security directory data.
    ///
    /// Returns the raw bytes to be appended to the file's overlay area.
    /// After appending, update the Security data directory with:
    /// - virtual_address = file offset where data was appended
    /// - size = returned size
    pub fn build(&self, directory: &SecurityDirectory) -> Vec<u8> {
        self.try_build(directory)
            .expect("certificate build failed: use try_build() for fallible serialization")
    }

    /// Build the security directory with checked lengths and alignments.
    pub fn try_build(&self, directory: &SecurityDirectory) -> Result<Vec<u8>> {
        if directory.certificates.is_empty() {
            return Ok(Vec::new());
        }

        let total_size = self.try_calculate_size(directory)?;
        let mut data = vec![0u8; total_size];
        let mut offset = 0;

        for cert in &directory.certificates {
            // Write length (header + data, unpadded)
            let cert_length = Certificate::HEADER_SIZE + cert.data.len();
            let cert_length_u32 = u32::try_from(cert_length)
                .map_err(|_| Error::invalid_data_directory("certificate length exceeds u32"))?;
            data[offset..offset + 4].copy_from_slice(&cert_length_u32.to_le_bytes());

            // Write revision
            data[offset + 4..offset + 6].copy_from_slice(&cert.revision.as_u16().to_le_bytes());

            // Write type
            data[offset + 6..offset + 8]
                .copy_from_slice(&cert.certificate_type.as_u16().to_le_bytes());

            // Write certificate data
            data[offset + 8..offset + 8 + cert.data.len()].copy_from_slice(&cert.data);

            // Move to next 8-byte aligned position
            offset += (cert_length + 7) & !7;
        }

        Ok(data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_certificate_header_size() {
        assert_eq!(Certificate::HEADER_SIZE, 8);
    }

    #[test]
    fn test_certificate_revision() {
        assert_eq!(
            CertificateRevision::from_u16(0x0100),
            CertificateRevision::Revision1
        );
        assert_eq!(
            CertificateRevision::from_u16(0x0200),
            CertificateRevision::Revision2
        );
        assert_eq!(
            CertificateRevision::from_u16(0x0300),
            CertificateRevision::Unknown(0x0300)
        );
    }

    #[test]
    fn test_certificate_type() {
        assert_eq!(
            CertificateType::from_u16(0x0002),
            CertificateType::PkcsSignedData
        );
        assert_eq!(
            CertificateType::from_u16(0x0000),
            CertificateType::Unknown(0x0000)
        );
    }

    #[test]
    fn test_certificate_buffer_too_small() {
        let data = [0u8; 7];
        assert!(Certificate::parse(&data).is_err());
    }

    #[test]
    fn test_builder_empty() {
        let builder = SecurityBuilder::new();
        let dir = SecurityDirectory::default();
        let data = builder.build(&dir);
        assert!(data.is_empty());
        assert_eq!(builder.calculate_size(&dir), 0);
    }

    #[test]
    fn test_builder_roundtrip() {
        let cert = Certificate {
            length: 0, // Will be calculated by builder
            revision: CertificateRevision::Revision2,
            certificate_type: CertificateType::PkcsSignedData,
            data: vec![0x30, 0x82, 0x01, 0x00], // Fake ASN.1 header
        };

        let dir = SecurityDirectory {
            certificates: vec![cert],
        };

        let builder = SecurityBuilder::new();
        let data = builder.build(&dir);

        // Parse it back
        let parsed = SecurityDirectory::parse(&data).unwrap();
        assert_eq!(parsed.certificates.len(), 1);
        assert_eq!(
            parsed.certificates[0].revision,
            CertificateRevision::Revision2
        );
        assert_eq!(
            parsed.certificates[0].certificate_type,
            CertificateType::PkcsSignedData
        );
        assert_eq!(parsed.certificates[0].data, vec![0x30, 0x82, 0x01, 0x00]);
    }

    #[test]
    fn test_builder_alignment() {
        // Certificates must be 8-byte aligned
        let cert = Certificate {
            length: 0,
            revision: CertificateRevision::Revision2,
            certificate_type: CertificateType::PkcsSignedData,
            data: vec![1, 2, 3], // 3 bytes data + 8 header = 11, rounds to 16
        };

        let dir = SecurityDirectory {
            certificates: vec![cert],
        };

        let builder = SecurityBuilder::new();
        let size = builder.calculate_size(&dir);
        assert_eq!(size % 8, 0); // Must be 8-byte aligned
        assert_eq!(size, 16); // 11 rounded up to 16
    }
}
