// This example shows how to disassemble some instructions
// and print them to stdout.

extern crate capstone_rust;

use capstone_rust::capstone as cs;

fn main() {
    // Buffer of code.
    let code = vec![0x55, 0x48, 0x8b, 0x05, 0xb8, 0x13, 0x00, 0x00];

    // Create a new instance of Capstone. This function accepts two parameters: the
    // architecture (x86 in this case) and the hardware mode (32 bit in this case).
    // As many other APIs `new` returns a `Result`, in a less trivial case you should
    // ensure that the API didn't fail.
    let dec = cs::Capstone::new(cs::cs_arch::CS_ARCH_X86, cs::cs_mode::CS_MODE_32).unwrap();

    // Disassemble the instructions. This function accepts three arguments: the code
    // buffer (a Vec<u8>), the address of the first instruction and the number of
    // instructions to decode (if zero, Capstone continues until the buffer is exhausted
    // or invalid data is found).
    let buf = dec.disasm(code, 0x100, 0).unwrap();

    // Iterate over the disassembled instructions and print them.
    for instr in buf.iter() {
        println!("0x{:x}:\t{}\t{}", instr.address, instr.mnemonic, instr.op_str);
    }
}
