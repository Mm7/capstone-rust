capstone-rust
=============
[![Build Status](https://travis-ci.org/Mm7/capstone-rust.svg?branch=master)](https://travis-ci.org/Mm7/capstone-rust)

Capstone engine wrapper for rust.

```rust
use capstone_rust::capstone as cs;
let code = vec![0x55, 0x48, 0x8b, 0x05, 0xb8, 0x13, 0x00, 0x00];

let dec = cs::Capstone::new(cs::cs_arch::CS_ARCH_X86, cs::cs_mode::CS_MODE_32).unwrap();
let buf = dec.disasm(code, 0, 0).unwrap();
for x in buf.iter() {
    println!("{:x}: {} {}", x.address, x.mnemonic, x.op_str);
}
```
