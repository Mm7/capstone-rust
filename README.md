# capstone-rust
[![Build Status](https://travis-ci.org/Mm7/capstone-rust.svg?branch=master)](https://travis-ci.org/Mm7/capstone-rust)

Rust bindings to Capstone engine.

### Dependencies

Install clang-3.9 (needed by [bindgen](https://github.com/servo/rust-bindgenbindgen)) and Capstone

```
sudo apt install llvm-3.9-dev libclang-3.9-dev clang-3.9 libcapstone3 libcapstone-dev
```

### Get started

Append to Cargo.toml:

```
[dependencies]
capstone_rust = "0.2.1"
```

Copy & paste an [example](https://github.com/Mm7/capstone-rust/tree/master/examples).
