//! Large bundled data files (FLIRT signature databases, Function ID packs).
//!
//! Native builds embed them with `include_bytes!`, exactly as before. The Emscripten (browser)
//! build leaves them out of the module so the ~50 MB of data downloads separately, is cached
//! by the browser, and can be limited to what a sample needs (one Function ID pack, not
//! both). The page mounts them under [`DIR`] in the module's in-memory file system before
//! running; a missing file is a contextual error, never a silent skip.

/// Where the host page mounts the data files on the Emscripten target.
#[cfg(target_os = "emscripten")]
pub const DIR: &str = "/sigs";

/// Yields `Result<Cow<'static, [u8]>, String>` for the file `sigs/$name`.
#[cfg(not(target_os = "emscripten"))]
macro_rules! bundled {
    ($name:literal) => {
        Ok::<std::borrow::Cow<'static, [u8]>, String>(std::borrow::Cow::Borrowed(include_bytes!(
            concat!(env!("CARGO_MANIFEST_DIR"), "/sigs/", $name)
        )))
    };
}

#[cfg(target_os = "emscripten")]
macro_rules! bundled {
    ($name:literal) => {
        $crate::bundled::read($name)
    };
}

pub(crate) use bundled;

#[cfg(target_os = "emscripten")]
pub fn read(name: &str) -> Result<std::borrow::Cow<'static, [u8]>, String> {
    let path = std::path::Path::new(DIR).join(name);
    std::fs::read(&path).map(std::borrow::Cow::Owned).map_err(|e| {
        format!(
            "bundled data file {} is not mounted: {e}",
            path.display()
        )
    })
}
