//! Security directory (Authenticode) parsing.
//!
//! The security directory contains WIN_CERTIFICATE structures for code signing.
//! Unlike other data directories, this one uses a **file offset** (not RVA).
//!
//! # Examples
//!
//! ```no_run
//! use portex::PE;
//!
//! let pe = PE::from_file("signed.exe")?;
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

use crate::{Error, Result};

/// WIN_CERTIFICATE revision values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum CertificateRevision {
    /// WIN_CERT_REVISION_1_0
    Revision1 = 0x0100,
    /// WIN_CERT_REVISION_2_0
    Revision2 = 0x0200,
}

impl CertificateRevision {
    /// Convert from raw u16.
    pub fn from_u16(value: u16) -> Option<Self> {
        match value {
            0x0100 => Some(Self::Revision1),
            0x0200 => Some(Self::Revision2),
            _ => None,
        }
    }
}

/// WIN_CERTIFICATE type values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum CertificateType {
    /// WIN_CERT_TYPE_X509 - X.509 certificate
    X509 = 0x0001,
    /// WIN_CERT_TYPE_PKCS_SIGNED_DATA - PKCS#7 SignedData
    PkcsSignedData = 0x0002,
    /// WIN_CERT_TYPE_RESERVED_1
    Reserved1 = 0x0003,
    /// WIN_CERT_TYPE_TS_STACK_SIGNED - Terminal Server Protocol Stack
    TsStackSigned = 0x0004,
}

impl CertificateType {
    /// Convert from raw u16.
    pub fn from_u16(value: u16) -> Option<Self> {
        match value {
            0x0001 => Some(Self::X509),
            0x0002 => Some(Self::PkcsSignedData),
            0x0003 => Some(Self::Reserved1),
            0x0004 => Some(Self::TsStackSigned),
            _ => None,
        }
    }
}

/// WIN_CERTIFICATE structure.
#[derive(Debug, Clone)]
pub struct Certificate {
    /// Total length including header and padding.
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

        let revision = CertificateRevision::from_u16(revision_raw).ok_or_else(|| {
            Error::invalid_data_directory(format!(
                "unknown certificate revision: {:#x}",
                revision_raw
            ))
        })?;

        let certificate_type = CertificateType::from_u16(cert_type_raw).ok_or_else(|| {
            Error::invalid_data_directory(format!("unknown certificate type: {:#x}", cert_type_raw))
        })?;

        let cert_data = data[Self::HEADER_SIZE..length].to_vec();

        // Certificates are 8-byte aligned
        let padded_length = (length + 7) & !7;

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
#[derive(Debug, Clone, Default)]
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
            // Need at least header size remaining
            if data.len() - offset < Certificate::HEADER_SIZE {
                break;
            }

            let (cert, consumed) = Certificate::parse(&data[offset..])?;
            certificates.push(cert);
            offset += consumed;
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
        let mut size = 0;
        for cert in &directory.certificates {
            // Header (8 bytes) + data, padded to 8-byte boundary
            let cert_size = Certificate::HEADER_SIZE + cert.data.len();
            size += (cert_size + 7) & !7;
        }
        size
    }

    /// Build the security directory data.
    ///
    /// Returns the raw bytes to be appended to the file's overlay area.
    /// After appending, update the Security data directory with:
    /// - virtual_address = file offset where data was appended
    /// - size = returned size
    pub fn build(&self, directory: &SecurityDirectory) -> Vec<u8> {
        if directory.certificates.is_empty() {
            return Vec::new();
        }

        let total_size = self.calculate_size(directory);
        let mut data = vec![0u8; total_size];
        let mut offset = 0;

        for cert in &directory.certificates {
            // Write length (header + data, unpadded)
            let cert_length = Certificate::HEADER_SIZE + cert.data.len();
            data[offset..offset + 4].copy_from_slice(&(cert_length as u32).to_le_bytes());

            // Write revision
            data[offset + 4..offset + 6].copy_from_slice(&(cert.revision as u16).to_le_bytes());

            // Write type
            data[offset + 6..offset + 8]
                .copy_from_slice(&(cert.certificate_type as u16).to_le_bytes());

            // Write certificate data
            data[offset + 8..offset + 8 + cert.data.len()].copy_from_slice(&cert.data);

            // Move to next 8-byte aligned position
            offset += (cert_length + 7) & !7;
        }

        data
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
            Some(CertificateRevision::Revision1)
        );
        assert_eq!(
            CertificateRevision::from_u16(0x0200),
            Some(CertificateRevision::Revision2)
        );
        assert_eq!(CertificateRevision::from_u16(0x0300), None);
    }

    #[test]
    fn test_certificate_type() {
        assert_eq!(
            CertificateType::from_u16(0x0002),
            Some(CertificateType::PkcsSignedData)
        );
        assert_eq!(CertificateType::from_u16(0x0000), None);
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
