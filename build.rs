fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::configure()
        .compile(
            &[
                "proto/key_transparency.proto",
                "proto/transparency.proto",
                "proto/prefix.proto"
            ],
            &["proto"],
        )?;
    Ok(())
}