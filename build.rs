use rustc_cfg::Cfg;
use std::env;

#[cfg(not(target_arch = "x86_64"))]
fn asm(_out_dir: &str) {}

#[cfg(target_arch = "x86_64")]
fn asm(out_dir: &str) {
    use std::process::Command;

    println!("cargo:rerun-if-changed=src/asm/x86_64/trampoline.asm");

    let status = Command::new("nasm")
        .arg("-f").arg("bin")
        .arg("-o").arg(format!("{}/trampoline", out_dir))
        .arg("src/asm/x86_64/trampoline.asm")
        .status()
        .expect("failed to run nasm");
    if ! status.success() {
        panic!("nasm failed with exit status {}", status);
    }
}

fn main() {
    println!("cargo:rustc-env=TARGET={}", env::var("TARGET").unwrap());

    let out_dir = env::var("OUT_DIR").unwrap();
    asm(&out_dir);

    // Build pre kstart init asm code for aarch64
    let cfg = Cfg::new(env::var_os("TARGET").unwrap()).unwrap();
    if cfg.target_arch == "aarch64" {
        println!("cargo:rerun-if-changed=src/arch/aarch64/init/pre_kstart/early_init.S");
        cc::Build::new()
            .file("src/arch/aarch64/init/pre_kstart/early_init.S")
            .target("aarch64-unknown-redox")
            .compile("early_init");
    }
}
