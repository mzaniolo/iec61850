// build.rs build script
use rasn_compiler::prelude::*;
use std::error::Error;

const BASE_PATH: &str = "src/mms/ans1";

fn main() -> Result<(), Box<dyn Error>> {
    // let files = ["presentation", "acse", "mms"];
    let files = ["mms"];

    for file in &files {
        println!("cargo::rerun-if-changed={}", ans1_file_path(file));
    }
    for file in &files {
        let config = RasnConfig {
            generate_from_impls: true,
            ..Default::default()
        };
        let warnings = Compiler::<RasnBackend, _>::new_with_config(config)
            .add_asn_by_path(ans1_file_path(file))
            .set_output_mode(rasn_compiler::OutputMode::SingleFile(
                rs_file_path(file).into(),
            ))
            .compile()
            .unwrap_or_else(|e| {
                panic!("Error compiling asn1 file {}: \n{e}", ans1_file_path(file))
            });
        for warning in warnings {
            println!("cargo::warning={}", warning);
        }
    }

    Ok(())
}

fn ans1_file_path(file: &str) -> String {
    format!("{BASE_PATH}/{}.asn1", file)
}

fn rs_file_path(file: &str) -> String {
    format!("{BASE_PATH}/{}.rs", file)
}
