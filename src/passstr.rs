// Based on myfreeweb/secstr

use std::fmt;
use std::borrow::Borrow;
use std::borrow::BorrowMut;
use crypto::digest::Digest;
use crypto::sha2::Sha512;
use libc;
use std::ptr;

#[derive(Hash)]
pub struct SecStr {
    content: Vec<u8>,
}

impl SecStr {
    pub fn new() -> SecStr {
        SecStr {
            content: Vec::new(),
        }
    }

    /// Borrow the contents of the string.
    pub fn unsecure(&self) -> &[u8] {
        self.borrow()
    }

    /// Mutably borrow the contents of the string.
    pub fn unsecure_mut(&mut self) -> &mut [u8] {
        self.borrow_mut()
    }

    pub fn get_vec(&self) -> Vec<u8> {
        self.content.clone()
    }

    pub fn push(&mut self, c: char) {
        memlock::mlock(&self.content);

        let mut hasher = Sha512::new();
        self.content.append(&mut format!("{}", c).into());

        hasher.input(&self.content[..]);

        self.content = hasher.result_str().into_bytes();
    }

    #[inline(never)]
    /// Overwrite the string with zeros. This is automatically called in the destructor.
    pub fn zero_out(&mut self) {
        unsafe {
            ptr::write_bytes(self.content.as_ptr() as *mut libc::c_void, 0, self.content.len());
        }
    }
}

// Creation
impl<T> From<T> for SecStr where T: Into<Vec<u8>> {
    fn from(s: T) -> SecStr {
        SecStr {
            content: s.into(),
        }
    }
}

// Borrowing
impl Borrow<[u8]> for SecStr {
    fn borrow(&self) -> &[u8] {
        self.content.borrow()
    }
}

impl BorrowMut<[u8]> for SecStr {
    fn borrow_mut(&mut self) -> &mut [u8] {
        self.content.borrow_mut()
    }
}

// Overwrite memory with zeros when we're done
impl Drop for SecStr {
    fn drop(&mut self) {
        self.zero_out();
        memlock::munlock(&self.content);
    }
}

// Constant time comparison
impl PartialEq for SecStr {
    #[inline(never)]
    fn eq(&self, other: &SecStr) -> bool {
        let ref us = self.content;
        let ref them = other.content;
        if us.len() != them.len() {
            return false;
        }
        let mut result = 0;
        for i in 0..us.len() {
            result |= us[i] ^ them[i];
        }
        result == 0
    }
}

// Make sure sensitive information is not logged accidentally
impl fmt::Debug for SecStr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("***SECRET***").map_err(|_| { fmt::Error })
    }
}

impl fmt::Display for SecStr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("***SECRET***").map_err(|_| { fmt::Error })
    }
}

mod memlock {
    extern crate libc;
    use self::libc::funcs::posix88::mman;

    pub fn mlock(cont: &Vec<u8>) {
        unsafe {
            mman::mlock(cont.as_ptr() as *const libc::c_void, cont.len() as libc::size_t);
        }
    }

    pub fn munlock(cont: &Vec<u8>) {
        unsafe {
            mman::munlock(cont.as_ptr() as *const libc::c_void, cont.len() as libc::size_t);
        }
    }
}
