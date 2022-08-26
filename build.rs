use rustc_cfg::Cfg;
use std::env;
use std::process::Command;

fn main() {
    println!("cargo:rustc-env=TARGET={}", env::var("TARGET").unwrap());

    let out_dir = env::var("OUT_DIR").unwrap();
    let cfg = Cfg::new(env::var_os("TARGET").unwrap()).unwrap();
    match cfg.target_arch.as_str() {
        "aarch64" => {
            // Build pre kstart init asm code for aarch64
            /*TODO: do we need any of this?
            println!("cargo:rerun-if-changed=src/arch/aarch64/init/pre_kstart/early_init.S");
            cc::Build::new()
                .file("src/arch/aarch64/init/pre_kstart/early_init.S")
                .target("aarch64-unknown-redox")
                .compile("early_init");
            */
        },
        "x86" => {
            println!("cargo:rerun-if-changed=src/asm/x86/trampoline.asm");

            let status = Command::new("nasm")
                .arg("-f").arg("bin")
                .arg("-o").arg(format!("{}/trampoline", out_dir))
                .arg("src/asm/x86/trampoline.asm")
                .status()
                .expect("failed to run nasm");
            if ! status.success() {
                panic!("nasm failed with exit status {}", status);
            }
        },
        "x86_64" => {
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
        _ => (),
    }
}
