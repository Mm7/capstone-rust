// This example shows how to share a `Capstone` instance
// among multiple threads.

extern crate capstone_rust;

use std::sync::Arc;
use std::thread;

use capstone_rust::capstone as cs;

fn main() {
    // Buffer of code.
    let code = vec![0x55, 0x48, 0x8b, 0x05, 0xb8, 0x13, 0x00, 0x00];
    let dec = Arc::new(cs::Capstone::new(cs::cs_arch::CS_ARCH_X86, cs::cs_mode::CS_MODE_32).unwrap());

    // Store the handles to threads.
    let mut handle = Vec::new();

	for _ in 0..10 {
        let dec = dec.clone();
        let code = code.clone();

		handle.push(thread::spawn(move || {
            let buf = dec.disasm(code.as_slice(), 0x100, 0).unwrap();
            for instr in buf.iter() {
                println!("0x{:x}:\t{}\t{}", instr.address, instr.mnemonic, instr.op_str);
            }
		}));
	}

    // Wait for threads to return.
    for i in handle {
        i.join().unwrap();
    }
}
