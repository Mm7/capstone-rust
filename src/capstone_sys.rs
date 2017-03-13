#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(improper_ctypes)]

use std::fmt;

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

// It seems that bindgen fails to derive Debug, Clone and Copy for `cs_arm`. Let's implement them
// traits manually.
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
