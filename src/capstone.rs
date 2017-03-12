extern crate libc;
extern crate libcapstone_sys;

pub use self::libcapstone_sys::*;

use std::cell::Cell;
use std::error::Error;
use std::ffi::CStr;
use std::fmt;

/// Get the version of the capstone engine.
///
/// Returns major, minor and combined. combined is (major << 8 | minor), and it encodes both
/// major & minor versions.
///
/// # Examples
///
/// ```
/// use capstone_rust::capstone as cs;
///
/// let (major, minor, combined) = cs::engine_version();
/// println!("Capstone version: {}.{}", major, minor);
/// assert_eq!(((major << 8) | minor) as u32, combined);
/// ```
pub fn engine_version() -> (i32, i32, u32) {
    let mut major: i32 = Default::default();
    let mut minor: i32 = Default::default();
    let combined;

    unsafe { combined = cs_version(&mut major, &mut minor); };

    (major, minor, combined)
}

/// Check if capstone supports an arch.
///
/// Returns `true` if `arch` is supported.
///
/// # Examples
///
/// ```
/// use capstone_rust::capstone as cs;
///
/// let supported = if cs::support_arch(cs::CS_ARCH_ARM) { "is" } else { "isn't" };
/// println!("The ARM architecture {} supported!", supported);
/// ```
pub fn support_arch(arch: cs_arch) -> bool {
    assert!(arch <= i32::max_value() as u32);
    unsafe { cs_support(arch as i32) }
}

/// Rust-friendly error wrapper over Capstone's low-level cs_err.
#[derive(Debug)]
pub struct CsErr {
    code: cs_err,
}

impl fmt::Display for CsErr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let strerr;
        unsafe { strerr = CStr::from_ptr(cs_strerror(self.code)) };
        let strerr = strerr.to_str().unwrap_or("Failed to creare the error message string");

        write!(f, "{}", strerr)
    }
}

impl Error for CsErr {
    fn description(&self) -> &str {
        let strerr;
        unsafe { strerr = CStr::from_ptr(cs_strerror(self.code)) };

        strerr.to_str().unwrap_or("Failed to creare the error message string")
    }
}

impl CsErr {
    /// Create a Capstone error from a low-level cs_err code.
    pub fn new(code: cs_err) -> CsErr {
        assert_ne!(code, CS_ERR_OK);
        CsErr{code: code}
    }

    /// Get the low-level cr_err code.
    pub fn code(&self) -> cs_err {
        self.code
    }
}

/// Convert a cs_err to a Result<(), CsErr>.
fn to_res(code: cs_err) -> Result<(), CsErr> {
    if code != CS_ERR_OK {
        Err(CsErr::new(code))
    } else {
        Ok(())
    }
}

/// Disassebled instruction.
///
/// A Rust-friendly struct to access fields of a disassembled instruction. This is a safe wrapper
/// over cs_insn.
#[derive(Debug)]
pub struct Instr {
    pub id: u32,
    pub address: u64,
    pub size: u16,
    pub bytes: Vec<u8>,
    pub mnemonic: String,
    pub op_str: String,
    pub detail: Option<()>,
}

impl Instr {
    /// Create an `Instr` from a cs_insn.
    pub fn new(instr: &cs_insn) -> Instr {
        let mut bytes = Vec::new();
        for i in 0..instr.bytes.len() {
            bytes.push(instr.bytes[i]);
        }

        let mut mnemonic = String::new();
        for i in 0..instr.mnemonic.len() {
            if instr.mnemonic[i] == 0 {
                break;
            }
            mnemonic.push((instr.mnemonic[i] as u8) as char);
        }

        let mut op_str = String::new();
        for i in 0..instr.op_str.len() {
            if instr.op_str[i] == 0 {
                break;
            }
            op_str.push((instr.op_str[i] as u8) as char);
        }

        Instr{
            id: instr.id,
            address: instr.address,
            size: instr.size,
            bytes: bytes,
            mnemonic: mnemonic,
            op_str: op_str,
            detail: None
        }
    }
}

/// Buffer of disassembled instructions.
///
/// Provides a Rust-friendly interface to read the buffer of instructions disassembled by Capstone.
pub struct InstrBuf {
    ptr: *mut cs_insn,
    count: usize,
}

impl Drop for InstrBuf {
    fn drop(&mut self) {
        unsafe { cs_free(self.ptr, self.count); }
    }
}

impl InstrBuf {
    /// Create an `InstrBuf` from a pointer to a cs_insn buffer. `count` is the number of
    /// instructions in `insn`.
    pub fn new(insn: *mut cs_insn, count: usize) -> InstrBuf {
        InstrBuf{ptr: insn, count: count}
    }

    /// Get the number of instructions in this buffer.
    pub fn count(&self) -> usize {
        self.count
    }

    /// Get the instruction at the requested index.
    pub fn get(&self, index: usize) -> Instr {
        assert!(index < self.count);
        let insn;

        unsafe { insn = &(*(self.ptr.offset(index as isize))) }
        Instr::new(insn)
    }

    /// Create an iterator from the beginning of this buffer.
    pub fn iter(&self) -> InstrIter {
        InstrIter::new(self)
    }
}

/// Disassembled instructions iterator.
///
/// Iterate over the instructions of a buffer of disassembled instructions.
pub struct InstrIter<'a> {
    buf: &'a InstrBuf,
    current: usize,
}

impl<'a> Iterator for InstrIter<'a> {
    type Item = Instr;

    fn next(&mut self) -> Option<Self::Item> {
        assert!(self.current <= self.buf.count());

        if self.current == self.buf.count() {
            None
        } else {
            let instr = self.buf.get(self.current);
            self.current += 1;
            Some(instr)
        }
    }
}

impl<'a> InstrIter<'a> {
    /// Create an `InstrIter` from the beginning of `buf`.
    pub fn new(buf: &InstrBuf) -> InstrIter {
        InstrIter{buf: buf, current: 0}
    }
}

/// Capstone handle.
pub struct Capstone {
    handle: Cell<csh>,
}

impl Drop for Capstone {
    fn drop(&mut self) {
        let err;

        unsafe { err = cs_close(self.handle.as_ptr()); }

        if err != CS_ERR_OK {
            panic!("{}", CsErr::new(err).description())
        }
    }
}

impl Capstone {
    /// Create a Capstone handle.
    ///
    /// `arch` architecture type (CS_ARCH_*), `mode` hardware mode (CS_MODE_*).
    pub fn new(arch: cs_arch, mode: cs_mode) -> Result<Capstone, CsErr> {
        let err;
        let mut handle = Default::default();

        unsafe { err = cs_open(arch, mode, &mut handle) };
        to_res(err)?;

        Ok(Capstone{handle: Cell::new(handle)})
    }

    /// Set option for disassembling engine at runtime.
    ///
    /// `typ` type of option to set. `value` value of the option.
    pub fn option(&self, typ: cs_opt_type, value: usize) -> Result<(), CsErr> {
        let err;

        unsafe { err = cs_option(self.handle.get(), typ, value); };
        to_res(err)
    }

    /// Disassemble binary code, given the code buffer, address and number of instructions to be
    /// decoded.
    ///
    /// `buf` is the code buffer. `addr` is the address of the first instruction, `count` is the
    /// number of instructions to decode, if `0` decode until the buffer is empty or an invalid
    /// instruction is found.
    ///
    /// Returns a buffer of decoded instructions or an error (in case of troubles).
    ///
    /// # Examples
    ///
    /// ```
    /// use capstone_rust::capstone as cs;
    /// let code = vec![0x55, 0x48, 0x8b, 0x05, 0xb8, 0x13, 0x00, 0x00];
    ///
    /// let dec = cs::Capstone::new(cs::CS_ARCH_X86, cs::CS_MODE_32).unwrap();
    /// let buf = dec.disasm(code, 0, 0).unwrap();
    /// for x in buf.iter() {
    ///     println!("{:x}: {} {}", x.address, x.mnemonic, x.op_str);
    /// }
    /// ```
    /// ```
    /// use capstone_rust::capstone as cs;
    /// let code = vec![0x55, 0x48, 0x8b, 0x05, 0xb8, 0x13, 0x00, 0x00];
    ///
    /// let dec = cs::Capstone::new(cs::CS_ARCH_X86, cs::CS_MODE_32).unwrap();
    /// let buf = dec.disasm(code, 0, 0).unwrap();
    /// assert_eq!(buf.get(0).mnemonic, "push");
    /// assert_eq!(buf.get(1).mnemonic, "dec");
    /// assert_eq!(buf.get(2).mnemonic, "mov");
    /// ```
    pub fn disasm(&self, buf: Vec<u8>, addr: u64, count: usize) -> Result<InstrBuf, CsErr> {
        let mut insn: *mut cs_insn = 0 as *mut cs_insn;
        let res;

        unsafe {
            res = cs_disasm(self.handle.get(), buf.as_ptr(), buf.len(), addr, count, &mut insn);
        }
        if res == 0 {
            let err = unsafe { cs_errno(self.handle.get()) };
            return Err(CsErr::new(err));
        }

        Ok(InstrBuf::new(insn, res))
    }

    /// Return friendly name of register in a string.
    ///
    /// Returns `None` if `reg_id` is invalid. You can find the register mapping in Capstone's
    /// C headers (e.g. x86.h for x86).
    ///
    /// # Examples
    ///
    /// ```
    /// use capstone_rust::capstone as cs;
    ///
    /// let dec = cs::Capstone::new(cs::CS_ARCH_X86, cs::CS_MODE_32).unwrap();
    /// assert_eq!(dec.reg_name(21).unwrap(), "ebx");
    /// ```
    pub fn reg_name(&self, reg_id: u32) -> Option<&str> {
        let name = unsafe {
            let name = cs_reg_name(self.handle.get(), reg_id);
            if name == 0 as *const i8 {
                return None;
            }
            CStr::from_ptr(name)
        };

        match name.to_str() {
            Ok(s)  => Some(s),
            Err(_) => None,
        }
    }
}
