use serde::Serialize;

#[derive(Debug, Default, Clone, Serialize)]
pub struct Argument {
    index: usize,
}

impl Argument {
    #[must_use]
    pub fn new(index: usize) -> Self {
        Self { index }
    }

    #[must_use]
    pub fn index(&self) -> usize {
        self.index
    }
}
