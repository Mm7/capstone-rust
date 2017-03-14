extern crate capstone_rust;

use capstone_rust::capstone as cs;
use std::mem::transmute;

#[test]
fn signle_instr() {
    let code = vec![0xe9, 0x0c, 0x00, 0x00, 0x00];
    let dec = cs::Capstone::new(cs::cs_arch::CS_ARCH_X86, cs::cs_mode::CS_MODE_32).unwrap();

    let buf = dec.disasm(code, 0, 0).unwrap();

    let jmp = buf.get(0);
    assert_eq!(jmp.mnemonic, "jmp");
    assert_eq!(jmp.op_str, "0x11");
    assert_eq!(jmp.address, 0);
    assert_eq!(jmp.id, unsafe { transmute::<cs::x86_insn, u32>(cs::x86_insn::X86_INS_JMP) } );
    assert_eq!(jmp.size, 5);
}

#[test]
fn multiple_instr() {
    let code = vec![0x83, 0xc3, 0x02, 0x66, 0xb8, 0x2c, 0x00, 0x55, 0x8d, 0x73, 0x10];
    let dec = cs::Capstone::new(cs::cs_arch::CS_ARCH_X86, cs::cs_mode::CS_MODE_32).unwrap();

    dec.option(cs::cs_opt_type::CS_OPT_DETAIL, cs::cs_opt_value::CS_OPT_ON).unwrap();

    let buf = dec.disasm(code, 0, 0).unwrap();

    let instr1 = buf.get(0);
    assert_eq!(instr1.mnemonic, "add");
    assert_eq!(instr1.op_str, "ebx, 2");
    assert_eq!(instr1.address, 0);
    assert_eq!(instr1.id, unsafe { transmute::<cs::x86_insn, u32>(cs::x86_insn::X86_INS_ADD) } );
    assert_eq!(instr1.size, 3);

    let instr2 = buf.get(1);
    assert_eq!(instr2.mnemonic, "mov");
    assert_eq!(instr2.op_str, "ax, 0x2c");
    assert_eq!(instr2.address, 3);
    assert_eq!(instr2.id, unsafe { transmute::<cs::x86_insn, u32>(cs::x86_insn::X86_INS_MOV) } );
    assert_eq!(instr2.size, 4);

    let instr3 = buf.get(2);
    assert_eq!(instr3.mnemonic, "push");
    assert_eq!(instr3.op_str, "ebp");
    assert_eq!(instr3.address, 7);
    assert_eq!(instr3.id, unsafe { transmute::<cs::x86_insn, u32>(cs::x86_insn::X86_INS_PUSH) } );
    assert_eq!(instr3.size, 1);

    let instr4 = buf.get(3);
    assert_eq!(instr4.mnemonic, "lea");
    assert_eq!(instr4.op_str, "esi, dword ptr [ebx + 0x10]");
    assert_eq!(instr4.address, 8);
    assert_eq!(instr4.id, unsafe { transmute::<cs::x86_insn, u32>(cs::x86_insn::X86_INS_LEA) } );
    assert_eq!(instr4.size, 3);
}
