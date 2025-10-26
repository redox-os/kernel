use std::{env, path::Path, process::Command};
use toml::Table;

fn parse_kconfig(arch: &str) -> Option<()> {
    println!("cargo:rerun-if-changed=config.toml");

    assert!(Path::new("config.toml.example").try_exists().unwrap());
    if !Path::new("config.toml").try_exists().unwrap() {
        std::fs::copy("config.toml.example", "config.toml").unwrap();
    }
    let config_str = std::fs::read_to_string("config.toml").unwrap();
    let root: Table = toml::from_str(&config_str).unwrap();

    let altfeatures = root
        .get("arch")?
        .as_table()
        .unwrap()
        .get(arch)?
        .as_table()
        .unwrap()
        .get("features")?
        .as_table()
        .unwrap();

    #[expect(clippy::format_collect)] // TODO: remove once version is bumped
    let features_list = altfeatures
        .keys()
        .map(|feat| format!(", {feat:?}"))
        .collect::<String>();
    println!("cargo::rustc-check-cfg=cfg(cpu_feature_always, values(\"\"{features_list}))");
    println!("cargo::rustc-check-cfg=cfg(cpu_feature_auto, values(\"\"{features_list}))");
    println!("cargo::rustc-check-cfg=cfg(cpu_feature_never, values(\"\"{features_list}))");

    let self_modifying = env::var("CARGO_FEATURE_SELF_MODIFYING").is_ok();

    for (name, value) in altfeatures {
        let mut choice = value.as_str().unwrap();
        assert!(matches!(choice, "always" | "never" | "auto"));

        if !self_modifying && choice == "auto" {
            choice = "never";
        }

        println!("cargo:rustc-cfg=cpu_feature_{choice}=\"{name}\"");
    }

    Some(())
}

fn main() {
    println!("cargo::rustc-env=TARGET={}", env::var("TARGET").unwrap());
    println!("cargo::rustc-check-cfg=cfg(dtb)");

    let out_dir = env::var("OUT_DIR").unwrap();
    let arch_str = env::var("CARGO_CFG_TARGET_ARCH").unwrap();

    match &*arch_str {
        "aarch64" => {
            println!("cargo::rustc-cfg=dtb");
        }
        "x86" => {
            println!("cargo::rerun-if-changed=src/asm/x86/trampoline.asm");

            let status = Command::new("nasm")
                .arg("-f")
                .arg("bin")
                .arg("-o")
                .arg(format!("{}/trampoline", out_dir))
                .arg("src/asm/x86/trampoline.asm")
                .status()
                .expect("failed to run nasm");
            if !status.success() {
                panic!("nasm failed with exit status {}", status);
            }
        }
        "x86_64" => {
            println!("cargo::rerun-if-changed=src/asm/x86_64/trampoline.asm");

            let status = Command::new("nasm")
                .arg("-f")
                .arg("bin")
                .arg("-o")
                .arg(format!("{}/trampoline", out_dir))
                .arg("src/asm/x86_64/trampoline.asm")
                .status()
                .expect("failed to run nasm");
            if !status.success() {
                panic!("nasm failed with exit status {}", status);
            }
        }
        "riscv64" => {
            println!("cargo::rustc-cfg=dtb");
        }
        _ => (),
    }

    let _ = parse_kconfig(&*arch_str);
}
