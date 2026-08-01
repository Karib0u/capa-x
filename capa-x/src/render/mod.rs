//! Text renderers for [`crate::rd::ResultDocument`], ported from
//! `capa/render/{default,verbose,vverbose}.py`.
//!
//! These render plain indented text, not `rich` tables: by design,
//! text-output parity is judged on content and order ("same rules, same
//! order, same addresses"), extracted by a tolerant parser in
//! `scripts/difftest.py`, not exact box-drawing characters.

pub mod default;
mod utils;
pub mod verbose;
pub mod vverbose;
