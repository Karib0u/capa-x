pub fn main() -> dnfile::Result<()> {
    let Some(arg) = std::env::args().nth(1) else {
        eprintln!("usage: dnfile <path-to-.NET-PE>");
        std::process::exit(2);
    };
    let data = std::fs::read(&arg)?;
    let df = dnfile::DnPe::parse(&data)?;
    println!("{df:#02x?}");
    Ok(())
}
