//! Shared bounded parsing helpers.

use crate::prelude::*;
use crate::{Error, Result};

/// Read exactly `len` bytes from an RVA callback.
pub(crate) fn read_exact_rva<F>(
    read_at_rva: &F,
    rva: u32,
    len: usize,
    context: &str,
) -> Result<Vec<u8>>
where
    F: Fn(u32, usize) -> Option<Vec<u8>>,
{
    let data = read_at_rva(rva, len).ok_or_else(|| Error::invalid_rva(rva))?;
    if data.len() != len {
        return Err(Error::invalid_data_directory(format!(
            "{context} returned {} bytes, expected {len}",
            data.len()
        )));
    }
    Ok(data)
}

/// Read a required null-terminated UTF-8 string without requiring `max_len`
/// bytes to exist after the string in the image.
pub(crate) fn read_c_string<F>(
    read_at_rva: &F,
    rva: u32,
    max_len: usize,
    context: &str,
) -> Result<String>
where
    F: Fn(u32, usize) -> Option<Vec<u8>>,
{
    let mut bytes = Vec::new();
    for index in 0..max_len {
        let offset = u32::try_from(index)
            .ok()
            .and_then(|offset| rva.checked_add(offset))
            .ok_or_else(|| Error::invalid_data_directory(format!("{context} RVA overflow")))?;
        let byte = read_at_rva(offset, 1)
            .and_then(|data| data.first().copied())
            .ok_or_else(|| Error::invalid_rva(offset))?;
        if byte == 0 {
            return String::from_utf8(bytes).map_err(|_| Error::invalid_utf8());
        }
        bytes.push(byte);
    }
    Err(Error::invalid_data_directory(format!(
        "{context} is not null-terminated within {max_len} bytes"
    )))
}

/// Read a C string whose bytes must remain inside an enclosing RVA range.
pub(crate) fn read_c_string_in_range<F>(
    read_at_rva: &F,
    rva: u32,
    enclosing_rva: u32,
    enclosing_size: u32,
    max_len: usize,
    context: &str,
) -> Result<String>
where
    F: Fn(u32, usize) -> Option<Vec<u8>>,
{
    let enclosing_end = u64::from(enclosing_rva)
        .checked_add(u64::from(enclosing_size))
        .ok_or_else(|| Error::invalid_data_directory("data-directory RVA overflow"))?;
    if u64::from(rva) < u64::from(enclosing_rva) || u64::from(rva) >= enclosing_end {
        return Err(Error::invalid_data_directory(format!(
            "{context} RVA {:#x} is outside {:#x}..{:#x}",
            rva, enclosing_rva, enclosing_end
        )));
    }
    let available = usize::try_from(enclosing_end - u64::from(rva)).unwrap_or(usize::MAX);
    read_c_string(read_at_rva, rva, max_len.min(available), context)
}

/// Validate that a fixed-width table fits in an enclosing RVA range.
pub(crate) fn bounded_table_range(
    table_rva: u32,
    count: u32,
    entry_size: usize,
    enclosing_rva: u32,
    enclosing_size: u32,
    context: &str,
) -> Result<()> {
    if count == 0 {
        return Ok(());
    }
    let byte_count = u64::from(count)
        .checked_mul(entry_size as u64)
        .ok_or_else(|| Error::invalid_data_directory(format!("{context} size overflow")))?;
    let table_end = u64::from(table_rva)
        .checked_add(byte_count)
        .ok_or_else(|| Error::invalid_data_directory(format!("{context} RVA overflow")))?;
    let enclosing_end = u64::from(enclosing_rva)
        .checked_add(u64::from(enclosing_size))
        .ok_or_else(|| Error::invalid_data_directory("data-directory RVA overflow"))?;
    if u64::from(table_rva) < u64::from(enclosing_rva) || table_end > enclosing_end {
        return Err(Error::invalid_data_directory(format!(
            "{context} range {:#x}..{:#x} is outside {:#x}..{:#x}",
            table_rva, table_end, enclosing_rva, enclosing_end
        )));
    }
    Ok(())
}
