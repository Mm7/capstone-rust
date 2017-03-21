// This example shows how to get operands details.

extern crate capstone_rust;

use capstone_rust::capstone as cs;

fn main() {
    // Buffer of code.
    let code = vec![0x01, 0xc0, 0x33, 0x19, 0x66, 0x83, 0xeb, 0x0a, 0xe8, 0x0c, 0x00, 0x00,
                    0x00, 0x21, 0x5c, 0xca, 0xfd];
    let dec = cs::Capstone::new(cs::cs_arch::CS_ARCH_X86, cs::cs_mode::CS_MODE_32).unwrap();

    // Enable detail mode. This is needed if you want to get instruction details.
    dec.option(cs::cs_opt_type::CS_OPT_DETAIL, cs::cs_opt_value::CS_OPT_ON).unwrap();

    let buf = dec.disasm(code.as_slice(), 0x100, 0).unwrap();

    for instr in buf.iter() {
        println!("0x{:x}:\t{}\t{}", instr.address, instr.mnemonic, instr.op_str);
        
        let details = instr.detail.unwrap();

        // Get the arch-specific part of details.
        if let cs::DetailsArch::X86(arch) = details.arch {

            for i in 0..arch.op_count {
                // Get the current operand.
                let op: cs::cs_x86_op = arch.operands[i as usize];

                match op.type_ {
                    cs::x86_op_type::X86_OP_REG => {
                        let reg: &cs::x86_reg = op.reg();
                        println!("  Register operand: {}", dec.reg_name(reg.as_int()).unwrap());
                        // note: reg can be printed also with the `{:?}` formatter.
                    },
                    cs::x86_op_type::X86_OP_IMM => {
                        let imm: i64 = op.imm();
                        println!("  Immediate operand: 0x{:x}", imm);
                    },
                    cs::x86_op_type::X86_OP_FP => {
                        let fp: f64 = op.fp();
                        println!("  Floating-point operand: {}", fp);
                    },
                    cs::x86_op_type::X86_OP_MEM => {
                        let mem: &cs::x86_op_mem = op.mem();
                        println!("  Memory operand:");
                        println!("      segment: {}", mem.segment);
                        println!("      base:    {}", mem.base);
                        println!("      index:   {}", mem.index);
                        println!("      scale:   {}", mem.scale);
                        println!("      disp:    {}", mem.disp);
                    },
                    cs::x86_op_type::X86_OP_INVALID => {
                        println!("  Invalid operand");
                    },
                };
            }
        }

    }
}
