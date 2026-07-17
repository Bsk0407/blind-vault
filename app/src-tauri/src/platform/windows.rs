use std::ffi::{c_void, OsStr};
use std::mem::zeroed;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::ptr::null_mut;
use std::slice;
use windows_sys::Win32::Foundation::{GetLastError, ERROR_NOT_FOUND};
use windows_sys::Win32::Security::Credentials::{
    CredDeleteW, CredFree, CredReadW, CredWriteW, CREDENTIALW, CRED_PERSIST_LOCAL_MACHINE,
    CRED_TYPE_GENERIC,
};
use windows_sys::Win32::Storage::FileSystem::{
    MoveFileExW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
};
use zeroize::{Zeroize, Zeroizing};

const PREFIX: &str = "BlindVault:v1:";
const MAX_CREDENTIAL_BYTES: usize = 5 * 512;

fn wide(value: &OsStr) -> Vec<u16> {
    value.encode_wide().chain(std::iter::once(0)).collect()
}

fn target(name: &str) -> Vec<u16> {
    wide(OsStr::new(&format!("{PREFIX}{}", name.to_lowercase())))
}

fn last_error(action: &str) -> String {
    let code = unsafe { GetLastError() };
    format!("{action}: {}", std::io::Error::from_raw_os_error(code as i32))
}

pub fn store_secret(name: &str, value: &str, _account: &str) -> Result<(), String> {
    let mut value_bytes = value.as_bytes().to_vec();
    if value_bytes.is_empty() {
        return Err("empty value — nothing stored".into());
    }
    if value_bytes.len() > MAX_CREDENTIAL_BYTES {
        value_bytes.zeroize();
        return Err(format!(
            "secret is larger than Windows Credential Manager's {MAX_CREDENTIAL_BYTES}-byte limit"
        ));
    }

    let mut target_name = target(name);
    let credential = CREDENTIALW {
        Flags: 0,
        Type: CRED_TYPE_GENERIC,
        TargetName: target_name.as_mut_ptr(),
        Comment: null_mut(),
        LastWritten: unsafe { zeroed() },
        CredentialBlobSize: value_bytes.len() as u32,
        CredentialBlob: value_bytes.as_mut_ptr(),
        Persist: CRED_PERSIST_LOCAL_MACHINE,
        AttributeCount: 0,
        Attributes: null_mut(),
        TargetAlias: null_mut(),
        UserName: null_mut(),
    };

    let written = unsafe { CredWriteW(&credential, 0) };
    value_bytes.zeroize();
    target_name.zeroize();
    if written == 0 {
        return Err(last_error("Credential Manager write failed"));
    }
    Ok(())
}

struct OwnedCredential(*mut CREDENTIALW);

impl Drop for OwnedCredential {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { CredFree(self.0.cast::<c_void>()) };
        }
    }
}

pub fn read_secret(name: &str) -> Result<Zeroizing<String>, String> {
    let mut target_name = target(name);
    let mut raw = null_mut();
    let found = unsafe { CredReadW(target_name.as_ptr(), CRED_TYPE_GENERIC, 0, &mut raw) };
    target_name.zeroize();
    if found == 0 {
        return Err(last_error("Credential Manager lookup failed"));
    }
    let owned = OwnedCredential(raw);
    let credential = unsafe { &*owned.0 };
    if credential.CredentialBlobSize == 0 || credential.CredentialBlob.is_null() {
        return Err("Credential Manager returned an empty secret".into());
    }
    let bytes = unsafe {
        slice::from_raw_parts(
            credential.CredentialBlob,
            credential.CredentialBlobSize as usize,
        )
    };
    let copied = bytes.to_vec();
    match String::from_utf8(copied) {
        Ok(decoded) => Ok(Zeroizing::new(decoded)),
        Err(error) => {
            let mut invalid = error.into_bytes();
            invalid.zeroize();
            Err("Credential Manager value is not valid UTF-8".into())
        }
    }
}

pub fn delete_secret(name: &str) -> Result<(), String> {
    let mut target_name = target(name);
    let deleted = unsafe { CredDeleteW(target_name.as_ptr(), CRED_TYPE_GENERIC, 0) };
    target_name.zeroize();
    if deleted != 0 {
        return Ok(());
    }
    let code = unsafe { GetLastError() };
    if code == ERROR_NOT_FOUND {
        return Ok(());
    }
    Err(format!(
        "Credential Manager delete failed: {}",
        std::io::Error::from_raw_os_error(code as i32)
    ))
}

pub fn replace_file(source: &Path, destination: &Path) -> Result<(), String> {
    let source_wide = wide(source.as_os_str());
    let destination_wide = wide(destination.as_os_str());
    let moved = unsafe {
        MoveFileExW(
            source_wide.as_ptr(),
            destination_wide.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if moved == 0 {
        return Err(last_error("atomic manifest replace failed"));
    }
    Ok(())
}

pub fn default_account() -> String {
    std::env::var("USERNAME").unwrap_or_else(|_| "unknown".into())
}

pub fn backend_id() -> &'static str {
    "windows-credential-manager"
}

pub fn backend_label() -> &'static str {
    "Windows Credential Manager"
}

pub fn names_equal(left: &str, right: &str) -> bool {
    left.eq_ignore_ascii_case(right)
}
