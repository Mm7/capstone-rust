// This example shows how to get the semantic group of an instruction.

extern crate capstone_rust;

use capstone_rust::capstone as cs;

fn main() {
    // Buffer of code.
    let code = vec![0xc3, 0xe9, 0x0b, 0x00, 0x00, 0x00, 0xe8, 0x06, 0x00, 0x00, 0x00];
    let dec = cs::Capstone::new(cs::cs_arch::CS_ARCH_X86, cs::cs_mode::CS_MODE_32).unwrap();

    // Enable detail mode. This is needed if you want to get instruction details.
    dec.option(cs::cs_opt_type::CS_OPT_DETAIL, cs::cs_opt_value::CS_OPT_ON).unwrap();

    let buf = dec.disasm(code, 0x100, 0).unwrap();

    for instr in buf.iter() {
        println!("0x{:x}:\t{}\t{}", instr.address, instr.mnemonic, instr.op_str);
        
        let details = instr.detail.unwrap();

        if details.groups.len() != 0 {
            print!("    This instruction belongs to groups:");
            for group in details.groups.iter() {
                print!(" {}", dec.group_name(*group).unwrap());
            }
            print!("\n");
        }

    }
}
