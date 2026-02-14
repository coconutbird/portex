//! PE checksum calculation.
//!
//! The PE checksum algorithm is used to verify integrity of PE files,
//! particularly for drivers and system files.

/// Calculate the PE checksum for a file.
/// 
/// The algorithm:
/// 1. Sum all 16-bit words, using 32-bit arithmetic with carry-add
/// 2. Skip the checksum field itself (at offset checksum_offset)
/// 3. Fold the result to 16 bits
/// 4. Add the file size
pub fn calculate_checksum(data: &[u8], checksum_offset: usize) -> u32 {
    let mut sum: u64 = 0;
    let len = data.len();

    // Process 16-bit words
    let mut i = 0;
    while i + 1 < len {
        // Skip the checksum field (4 bytes at checksum_offset)
        if i >= checksum_offset && i < checksum_offset + 4 {
            i += 2;
            continue;
        }

        let word = u16::from_le_bytes([data[i], data[i + 1]]) as u64;
        sum += word;
        i += 2;
    }

    // Handle odd byte at end
    if i < len {
        sum += data[i] as u64;
    }

    // Fold to 32 bits with carry
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    // Add file size
    (sum as u32) + (len as u32)
}

/// Get the offset of the checksum field in the optional header.
/// Returns None if the PE is malformed or doesn't have an optional header.
pub fn checksum_field_offset(data: &[u8]) -> Option<usize> {
    // DOS header e_lfanew is at offset 0x3C
    if data.len() < 0x40 {
        return None;
    }

    let pe_offset = u32::from_le_bytes([data[0x3C], data[0x3D], data[0x3E], data[0x3F]]) as usize;

    // PE signature (4) + COFF header (20) + checksum is at offset 64 in optional header
    let checksum_offset = pe_offset + 4 + 20 + 64;

    if checksum_offset + 4 > data.len() {
        return None;
    }

    Some(checksum_offset)
}

/// Calculate and return the checksum for PE data.
/// Returns None if the checksum field offset cannot be determined.
pub fn compute_pe_checksum(data: &[u8]) -> Option<u32> {
    let offset = checksum_field_offset(data)?;
    Some(calculate_checksum(data, offset))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_checksum_field_offset() {
        // Minimal PE-like structure
        let mut data = vec![0u8; 256];
        // DOS signature
        data[0] = b'M';
        data[1] = b'Z';
        // e_lfanew pointing to PE header at 0x80
        data[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        // PE signature
        data[0x80] = b'P';
        data[0x81] = b'E';
        data[0x82] = 0;
        data[0x83] = 0;

        let offset = checksum_field_offset(&data);
        // PE offset (0x80) + signature (4) + COFF (20) + checksum offset in optional (64)
        assert_eq!(offset, Some(0x80 + 4 + 20 + 64));
    }

    #[test]
    fn test_calculate_checksum() {
        // Simple test with known data
        let data = vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        // No checksum field to skip (use offset beyond data)
        let checksum = calculate_checksum(&data, 1000);
        // Sum of words: 0x0201 + 0x0403 + 0x0605 + 0x0807 = 0x1410
        // Plus file size: 0x1410 + 8 = 0x1418
        assert_eq!(checksum, 0x1418);
    }
}

