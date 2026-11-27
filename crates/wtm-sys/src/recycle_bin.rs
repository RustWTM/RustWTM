//! Safe wrappers for querying and emptying the Windows Recycle Bin.

use windows::Win32::UI::Shell::{
    SHERB_NOCONFIRMATION, SHERB_NOPROGRESSUI, SHERB_NOSOUND, SHEmptyRecycleBinW, SHQUERYRBINFO,
    SHQueryRecycleBinW,
};
use windows::core::PCWSTR;

use crate::Result;

/// Current item count and total size in the Recycle Bin.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RecycleBinStats {
    pub bytes: u64,
    pub items: u64,
}

/// Queries the total size and item count across all Recycle Bins.
pub fn query_recycle_bin() -> Result<RecycleBinStats> {
    let mut info = SHQUERYRBINFO {
        cbSize: size_of::<SHQUERYRBINFO>() as u32,
        i64Size: 0,
        i64NumItems: 0,
    };
    // SAFETY: `info` is initialized with its exact struct size and valid for writes.
    unsafe { SHQueryRecycleBinW(PCWSTR::null(), &mut info) }?;
    Ok(RecycleBinStats {
        bytes: u64::try_from(info.i64Size).unwrap_or(0),
        items: u64::try_from(info.i64NumItems).unwrap_or(0),
    })
}

/// Empties the Recycle Bin silently without confirmation dialogs or sound.
pub fn empty_recycle_bin() -> Result<()> {
    let flags = SHERB_NOCONFIRMATION | SHERB_NOPROGRESSUI | SHERB_NOSOUND;
    // SAFETY: `None` HWND and null root path empty all Recycle Bins with silent flags.
    unsafe { SHEmptyRecycleBinW(None, PCWSTR::null(), flags) }?;
    Ok(())
}
