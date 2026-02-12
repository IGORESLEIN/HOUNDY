use std::fs::File;
use std::io::Write;
use zip::write::FileOptions;
use zip::ZipWriter;
use anyhow::Result;

pub fn create_zip(filename: &str, content_map: Vec<(&str, String)>) -> Result<()> {
    let file = File::create(filename)?;
    let mut zip = ZipWriter::new(file);

    let options = FileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated)
        .unix_permissions(0o755);

    for (name, content) in content_map {
        zip.start_file(name, options)?;
        zip.write_all(content.as_bytes())?;
    }

    zip.finish()?;
    Ok(())
}
