pub mod json;
pub mod terminal;

use crate::report::Report;

/// Something that can turn a set of analysis reports into a displayable
/// or writable string.
///
/// Always takes a *slice* of reports, never a single `&Report` — this is
/// the concrete mechanism behind batch-mode readiness: single-token
/// analysis just calls `render(&[one_report])`. No renderer, and no
/// caller of a renderer, ever needs a separate code path for "one" vs.
/// "many" — that distinction lives only in how many `Report`s get
/// collected before rendering, which is `main.rs`'s job, not the
/// renderer's.
pub trait Renderer {
    fn render(&self, reports: &[Report]) -> String;
}
