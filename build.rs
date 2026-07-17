fn main() -> Result<(), Box<dyn std::error::Error>> {
    let descriptor = std::path::PathBuf::from(std::env::var("OUT_DIR")?).join("kt_descriptor.bin");
    tonic_build::configure()
        // Emitted so the server can expose gRPC reflection.
        .file_descriptor_set_path(&descriptor)
        .compile(
            &[
                "proto/key_transparency.proto",
                "proto/transparency.proto",
                "proto/prefix.proto",
            ],
            &["proto"],
        )?;
    Ok(())
}
