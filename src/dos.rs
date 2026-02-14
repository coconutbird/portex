//! DOS Header structures and parsing.

use crate::reader::Reader;
use crate::{Error, Result};

/// DOS "MZ" signature.
pub const DOS_SIGNATURE: u16 = 0x5A4D; // "MZ"

/// DOS Header (IMAGE_DOS_HEADER).
///
/// The DOS header is the first structure in a PE file,
/// located at offset 0. It contains the DOS stub and
/// a pointer to the PE header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct DosHeader {
    /// Magic number ("MZ" = 0x5A4D).
    pub e_magic: u16,
    /// Bytes on last page of file.
    pub e_cblp: u16,
    /// Pages in file.
    pub e_cp: u16,
    /// Relocations.
    pub e_crlc: u16,
    /// Size of header in paragraphs.
    pub e_cparhdr: u16,
    /// Minimum extra paragraphs needed.
    pub e_minalloc: u16,
    /// Maximum extra paragraphs needed.
    pub e_maxalloc: u16,
    /// Initial (relative) SS value.
    pub e_ss: u16,
    /// Initial SP value.
    pub e_sp: u16,
    /// Checksum.
    pub e_csum: u16,
    /// Initial IP value.
    pub e_ip: u16,
    /// Initial (relative) CS value.
    pub e_cs: u16,
    /// File address of relocation table.
    pub e_lfarlc: u16,
    /// Overlay number.
    pub e_ovno: u16,
    /// Reserved words.
    pub e_res: [u16; 4],
    /// OEM identifier.
    pub e_oemid: u16,
    /// OEM information.
    pub e_oeminfo: u16,
    /// Reserved words.
    pub e_res2: [u16; 10],
    /// File address of new exe header (PE header offset).
    pub e_lfanew: i32,
}

impl DosHeader {
    /// Size of the DOS header in bytes.
    pub const SIZE: usize = 64;

    /// Parse a DOS header from a byte slice.
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < Self::SIZE {
            return Err(Error::BufferTooSmall {
                expected: Self::SIZE,
                actual: data.len(),
            });
        }

        let e_magic = u16::from_le_bytes([data[0], data[1]]);
        if e_magic != DOS_SIGNATURE {
            return Err(Error::InvalidDosSignature);
        }

        Ok(Self {
            e_magic,
            e_cblp: u16::from_le_bytes([data[2], data[3]]),
            e_cp: u16::from_le_bytes([data[4], data[5]]),
            e_crlc: u16::from_le_bytes([data[6], data[7]]),
            e_cparhdr: u16::from_le_bytes([data[8], data[9]]),
            e_minalloc: u16::from_le_bytes([data[10], data[11]]),
            e_maxalloc: u16::from_le_bytes([data[12], data[13]]),
            e_ss: u16::from_le_bytes([data[14], data[15]]),
            e_sp: u16::from_le_bytes([data[16], data[17]]),
            e_csum: u16::from_le_bytes([data[18], data[19]]),
            e_ip: u16::from_le_bytes([data[20], data[21]]),
            e_cs: u16::from_le_bytes([data[22], data[23]]),
            e_lfarlc: u16::from_le_bytes([data[24], data[25]]),
            e_ovno: u16::from_le_bytes([data[26], data[27]]),
            e_res: [
                u16::from_le_bytes([data[28], data[29]]),
                u16::from_le_bytes([data[30], data[31]]),
                u16::from_le_bytes([data[32], data[33]]),
                u16::from_le_bytes([data[34], data[35]]),
            ],
            e_oemid: u16::from_le_bytes([data[36], data[37]]),
            e_oeminfo: u16::from_le_bytes([data[38], data[39]]),
            e_res2: [
                u16::from_le_bytes([data[40], data[41]]),
                u16::from_le_bytes([data[42], data[43]]),
                u16::from_le_bytes([data[44], data[45]]),
                u16::from_le_bytes([data[46], data[47]]),
                u16::from_le_bytes([data[48], data[49]]),
                u16::from_le_bytes([data[50], data[51]]),
                u16::from_le_bytes([data[52], data[53]]),
                u16::from_le_bytes([data[54], data[55]]),
                u16::from_le_bytes([data[56], data[57]]),
                u16::from_le_bytes([data[58], data[59]]),
            ],
            e_lfanew: i32::from_le_bytes([data[60], data[61], data[62], data[63]]),
        })
    }

    /// Write the DOS header to a byte buffer.
    pub fn write(&self, buf: &mut [u8]) -> Result<()> {
        if buf.len() < Self::SIZE {
            return Err(Error::BufferTooSmall {
                expected: Self::SIZE,
                actual: buf.len(),
            });
        }

        buf[0..2].copy_from_slice(&self.e_magic.to_le_bytes());
        buf[2..4].copy_from_slice(&self.e_cblp.to_le_bytes());
        buf[4..6].copy_from_slice(&self.e_cp.to_le_bytes());
        buf[6..8].copy_from_slice(&self.e_crlc.to_le_bytes());
        buf[8..10].copy_from_slice(&self.e_cparhdr.to_le_bytes());
        buf[10..12].copy_from_slice(&self.e_minalloc.to_le_bytes());
        buf[12..14].copy_from_slice(&self.e_maxalloc.to_le_bytes());
        buf[14..16].copy_from_slice(&self.e_ss.to_le_bytes());
        buf[16..18].copy_from_slice(&self.e_sp.to_le_bytes());
        buf[18..20].copy_from_slice(&self.e_csum.to_le_bytes());
        buf[20..22].copy_from_slice(&self.e_ip.to_le_bytes());
        buf[22..24].copy_from_slice(&self.e_cs.to_le_bytes());
        buf[24..26].copy_from_slice(&self.e_lfarlc.to_le_bytes());
        buf[26..28].copy_from_slice(&self.e_ovno.to_le_bytes());
        for (i, val) in self.e_res.iter().enumerate() {
            buf[28 + i * 2..30 + i * 2].copy_from_slice(&val.to_le_bytes());
        }
        buf[36..38].copy_from_slice(&self.e_oemid.to_le_bytes());
        buf[38..40].copy_from_slice(&self.e_oeminfo.to_le_bytes());
        for (i, val) in self.e_res2.iter().enumerate() {
            buf[40 + i * 2..42 + i * 2].copy_from_slice(&val.to_le_bytes());
        }
        buf[60..64].copy_from_slice(&self.e_lfanew.to_le_bytes());

        Ok(())
    }

    /// Parse a DOS header from a Reader at the given offset.
    pub fn read_from<R: Reader>(reader: &R, offset: u64) -> Result<Self> {
        let mut buf = [0u8; Self::SIZE];
        reader.read_exact_at(offset, &mut buf)?;
        Self::parse(&buf)
    }

    /// Serialize the DOS header to a byte vector.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = vec![0u8; Self::SIZE];
        self.write(&mut buf).expect("buffer size is correct");
        buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dos_header_size() {
        assert_eq!(DosHeader::SIZE, 64);
    }

    #[test]
    fn test_dos_header_parse_too_small() {
        let data = [0u8; 32];
        let result = DosHeader::parse(&data);
        assert!(matches!(result, Err(Error::BufferTooSmall { .. })));
    }

    #[test]
    fn test_dos_header_invalid_signature() {
        let mut data = [0u8; 64];
        data[0] = 0x00;
        data[1] = 0x00;
        let result = DosHeader::parse(&data);
        assert!(matches!(result, Err(Error::InvalidDosSignature)));
    }

    #[test]
    fn test_dos_header_roundtrip() {
        let mut data = [0u8; 64];
        data[0] = 0x4D; // 'M'
        data[1] = 0x5A; // 'Z'
        data[60..64].copy_from_slice(&0x80i32.to_le_bytes());

        let header = DosHeader::parse(&data).unwrap();
        assert_eq!(header.e_magic, DOS_SIGNATURE);
        assert_eq!(header.e_lfanew, 0x80);

        let mut output = [0u8; 64];
        header.write(&mut output).unwrap();
        assert_eq!(data, output);
    }
}
