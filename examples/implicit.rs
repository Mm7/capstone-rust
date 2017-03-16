// This example shows how to extract out details on implicit registers
// being read by instructions.

extern crate capstone_rust;

use capstone_rust::capstone as cs;

fn main() {
    // Buffer of code.
    let code = vec![0x01, 0xc0, 0xe8, 0x06, 0x00, 0x00, 0x00];
    let dec = cs::Capstone::new(cs::cs_arch::CS_ARCH_X86, cs::cs_mode::CS_MODE_32).unwrap();

    // Enable detail mode. This is needed if you want to get instruction details.
    dec.option(cs::cs_opt_type::CS_OPT_DETAIL, cs::cs_opt_value::CS_OPT_ON).unwrap();

    let buf = dec.disasm(code, 0x100, 0).unwrap();

    for instr in buf.iter() {
        println!("0x{:x}:\t{}\t{}", instr.address, instr.mnemonic, instr.op_str);
        
        let details = instr.detail.unwrap();

        if details.regs_read.len() != 0 {
            print!("  Implicit registers read:");
            for read in details.regs_read.iter() {
                // `read` is an int that correspond to an arch-specific register. In order to
                // get its human readable name use `reg_name`.
                print!(" {}", dec.reg_name(*read).unwrap());
            }
            print!("\n");
        }

        if details.regs_write.len() != 0 {
            print!("  Implicit registers written:");
            for write in details.regs_write.iter() {
                print!(" {}", dec.reg_name(*write).unwrap());
            }
            print!("\n");
        }

    }
}
