extern crate capstone_rust;

use std::sync::Arc;
use std::thread;

use capstone_rust::capstone as cs;

#[test]
fn thread() {
    let code = vec![0x55, 0x48, 0x8b, 0x05, 0xb8, 0x13, 0x00, 0x00];
    let dec = Arc::new(cs::Capstone::new(cs::cs_arch::CS_ARCH_X86, cs::cs_mode::CS_MODE_32).unwrap());
	
    for _ in 0..10 {
        let dec = dec.clone();
        let code = code.clone();

		thread::spawn(move || {
            dec.disasm(code.as_slice(), 0x100, 0).unwrap();
		});
	}
}
