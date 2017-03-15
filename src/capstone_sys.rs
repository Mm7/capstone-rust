#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(improper_ctypes)]

use std::convert::From;
use std::fmt;
use std::mem::transmute;

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

// It seems that bindgen fails to derive Debug, Clone and Copy for `cs_arm`. Let's implement them
// manually.
impl fmt::Debug for cs_arm {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut operands = String::new();
        for i in self.operands.iter() {
            operands.push_str(format!(" {:?}", i).as_str());
        }

        write!(f, "cs_arm {{ usermode: {:?}, vector_size: {:?}, vector_data: {:?}, \
            cps_mode: {:?}, cps_flag: {:?}, cc: {:?}, update_flags: {:?}, writeback: {:?}, \
            mem_barrier: {:?}, op_count: {:?},{}}}", self.usermode, self.vector_size,
            self.vector_data, self.cps_mode, self.cps_flag, self.cc, self.update_flags,
            self.writeback, self.mem_barrier, self.op_count, operands)
    }
}

impl Clone for cs_arm {
    fn clone(&self) -> cs_arm {
        *self
    }
}

impl Copy for cs_arm { }

// Operand enum getters.
impl cs_x86_op {
    pub fn reg(&self) -> &x86_reg {
        return unsafe { self.__bindgen_anon_1.reg.as_ref() };
    }
    pub fn imm(&self) -> i64 {
        return unsafe { *self.__bindgen_anon_1.imm.as_ref() };
    }
    pub fn fp(&self) -> f64 {
        return unsafe { *self.__bindgen_anon_1.fp.as_ref() };
    }
    pub fn mem(&self) -> &x86_op_mem {
        return unsafe { self.__bindgen_anon_1.mem.as_ref() };
    }
}

impl cs_arm64_op {
    pub fn reg(&self) -> u32 {
        return unsafe { *self.__bindgen_anon_1.reg.as_ref() };
    }
    pub fn imm(&self) -> i64 {
        return unsafe { *self.__bindgen_anon_1.imm.as_ref() };
    }
    pub fn fp(&self) -> f64 {
        return unsafe { *self.__bindgen_anon_1.fp.as_ref() };
    }
    pub fn mem(&self) -> &arm64_op_mem {
        return unsafe { self.__bindgen_anon_1.mem.as_ref() };
    }
    pub fn pstate(&self) -> &arm64_pstate {
        return unsafe { self.__bindgen_anon_1.pstate.as_ref() };
    }
    pub fn sys(&self) -> u32 {
        return unsafe { *self.__bindgen_anon_1.sys.as_ref() };
    }
    pub fn prefetch(&self) -> &arm64_prefetch_op {
        return unsafe { self.__bindgen_anon_1.prefetch.as_ref() };
    }
    pub fn barrier(&self) -> &arm64_barrier_op {
        return unsafe { self.__bindgen_anon_1.barrier.as_ref() };
    }

}

impl cs_arm_op {
    pub fn reg(&self) -> u32 {
        return unsafe { *self.__bindgen_anon_1.reg.as_ref() };
    }
    pub fn imm(&self) -> i32 {
        return unsafe { *self.__bindgen_anon_1.imm.as_ref() };
    }
    pub fn fp(&self) -> f64 {
        return unsafe { *self.__bindgen_anon_1.fp.as_ref() };
    }
    pub fn mem(&self) -> &arm_op_mem {
        return unsafe { self.__bindgen_anon_1.mem.as_ref() };
    }
    pub fn setend(&self) -> &arm_setend_type {
        return unsafe { self.__bindgen_anon_1.setend.as_ref() };
    }
}

impl cs_mips_op {
    pub fn reg(&self) -> u32 {
        return unsafe { *self.__bindgen_anon_1.reg.as_ref() };
    }
    pub fn imm(&self) -> i64 {
        return unsafe { *self.__bindgen_anon_1.imm.as_ref() };
    }
    pub fn mem(&self) -> &mips_op_mem {
        return unsafe { self.__bindgen_anon_1.mem.as_ref() };
    }
}

impl cs_ppc_op {
    pub fn reg(&self) -> u32 {
        return unsafe { *self.__bindgen_anon_1.reg.as_ref() };
    }
    pub fn imm(&self) -> i32 {
        return unsafe { *self.__bindgen_anon_1.imm.as_ref() };
    }
    pub fn mem(&self) -> &ppc_op_mem {
        return unsafe { self.__bindgen_anon_1.mem.as_ref() };
    }
    pub fn crx(&self) -> &ppc_op_crx {
        return unsafe { self.__bindgen_anon_1.crx.as_ref() };
    }
}

impl cs_sparc_op {
    pub fn reg(&self) -> u32 {
        return unsafe { *self.__bindgen_anon_1.reg.as_ref() };
    }
    pub fn imm(&self) -> i32 {
        return unsafe { *self.__bindgen_anon_1.imm.as_ref() };
    }
    pub fn mem(&self) -> &sparc_op_mem {
        return unsafe { self.__bindgen_anon_1.mem.as_ref() };
    }
}

impl cs_sysz_op {
    pub fn reg(&self) -> u32 {
        return unsafe { *self.__bindgen_anon_1.reg.as_ref() };
    }
    pub fn imm(&self) -> i64 {
        return unsafe { *self.__bindgen_anon_1.imm.as_ref() };
    }
    pub fn mem(&self) -> &sysz_op_mem {
        return unsafe { self.__bindgen_anon_1.mem.as_ref() };
    }
}

impl cs_xcore_op {
    pub fn reg(&self) -> u32 {
        return unsafe { *self.__bindgen_anon_1.reg.as_ref() };
    }
    pub fn imm(&self) -> i32 {
        return unsafe { *self.__bindgen_anon_1.imm.as_ref() };
    }
    pub fn mem(&self) -> &xcore_op_mem {
        return unsafe { self.__bindgen_anon_1.mem.as_ref() };
    }
}

// Register: enum <-> integer
impl From<u32> for x86_reg {
    fn from(i: u32) -> Self {
        return unsafe { transmute::<u32, Self>(i) }
    }
}
impl x86_reg {
    pub fn as_int(&self) -> u32 {
        return unsafe { transmute::<Self, u32>(*self) }
    }
}

impl From<u32> for arm64_reg {
    fn from(i: u32) -> Self {
        return unsafe { transmute::<u32, Self>(i) }
    }
}
impl arm64_reg {
    pub fn as_int(&self) -> u32 {
        return unsafe { transmute::<Self, u32>(*self) }
    }
}

impl From<u32> for arm_reg {
    fn from(i: u32) -> Self {
        return unsafe { transmute::<u32, Self>(i) }
    }
}
impl arm_reg {
    pub fn as_int(&self) -> u32 {
        return unsafe { transmute::<Self, u32>(*self) }
    }
}

impl From<u32> for mips_reg {
    fn from(i: u32) -> Self {
        return unsafe { transmute::<u32, Self>(i) }
    }
}
impl mips_reg {
    pub fn as_int(&self) -> u32 {
        return unsafe { transmute::<Self, u32>(*self) }
    }
}

impl From<u32> for ppc_reg {
    fn from(i: u32) -> Self {
        return unsafe { transmute::<u32, Self>(i) }
    }
}
impl ppc_reg {
    pub fn as_int(&self) -> u32 {
        return unsafe { transmute::<Self, u32>(*self) }
    }
}

impl From<u32> for sparc_reg {
    fn from(i: u32) -> Self {
        return unsafe { transmute::<u32, Self>(i) }
    }
}
impl sparc_reg {
    pub fn as_int(&self) -> u32 {
        return unsafe { transmute::<Self, u32>(*self) }
    }
}

impl From<u32> for sysz_reg {
    fn from(i: u32) -> Self {
        return unsafe { transmute::<u32, Self>(i) }
    }
}
impl sysz_reg {
    pub fn as_int(&self) -> u32 {
        return unsafe { transmute::<Self, u32>(*self) }
    }
}

impl From<u32> for xcore_reg {
    fn from(i: u32) -> Self {
        return unsafe { transmute::<u32, Self>(i) }
    }
}
impl xcore_reg {
    pub fn as_int(&self) -> u32 {
        return unsafe { transmute::<Self, u32>(*self) }
    }
}
