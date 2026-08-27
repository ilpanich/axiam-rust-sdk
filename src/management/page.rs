//! Pagination for the §27 management surface.
//!
//! Twenty of the 146 operations take `offset`/`limit` and answer with the
//! envelope `{ items, total, offset, limit }`. The other thirteen collection
//! reads answer with a bare array and are **not** paginated — §27.4 rule 4
//! forbids modelling those as a page, because a `Page` that reports
//! `total == items.len()` is indistinguishable from a real one right up to the
//! moment a caller relies on `total`.

use serde::Deserialize;

use crate::AxiamError;

/// Where a paginated read starts, how much of it to take, and what to filter
/// it by.
///
/// [`Default`] is offset 0 with no explicit limit and no search term, which
/// lets the server apply its own. §27.4 rule 4 is the reason this type does
/// **not** default `limit` to some SDK-chosen number: a client-side default
/// silently truncates, and the caller has no way to tell a short page from a
/// complete one.
///
/// [`search`](Self::search) lives here rather than as a third argument on each
/// of the twenty generated `list` methods, which is what §27.4 rule 4 requires:
/// the term is part of *which page this is*, not an unrelated filter. That is
/// also what makes [`collect_pages`] carry it across the whole walk for free —
/// a walk that filtered the first request and not the rest would return the
/// unfiltered tail.
///
/// This type is [`Clone`] but **not** [`Copy`], which it was before the search
/// term existed: an owned `String` cannot be copied bit-for-bit. Call sites
/// that relied on the implicit copy need an explicit `.clone()`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PageRequest {
    /// How many items to skip. `0` starts at the beginning.
    pub offset: u64,
    /// How many items to take. `None` lets the server decide.
    pub limit: Option<u64>,
    /// Free-text filter applied by the **server**, before `offset`/`limit`.
    ///
    /// Matched case-insensitively against the identifying fields of whatever is
    /// being listed — a name or username, plus the record id, so a UUID from a
    /// log line can be pasted in as-is. `total` on the resulting [`Page`] counts
    /// *matches*, not rows, which is what lets a pager built on it show a page
    /// count that belongs to the result set it is paging.
    ///
    /// `None` sends no `search` parameter at all. A term that is empty or all
    /// whitespace is treated as `None` (§27.4 rule 4): a search box that emits a
    /// request on every keystroke must not ask a different question once it has
    /// been cleared.
    ///
    /// The server caps the term's length. This SDK deliberately does not
    /// re-implement that cap — a client-side truncation the server would not
    /// have made is a silently different query.
    pub search: Option<String>,
}

impl PageRequest {
    /// A request for the first page, of `limit` items.
    pub fn first(limit: u64) -> Self {
        Self {
            offset: 0,
            limit: Some(limit),
            search: None,
        }
    }

    /// A request starting at `offset`, of `limit` items.
    pub fn new(offset: u64, limit: u64) -> Self {
        Self {
            offset,
            limit: Some(limit),
            search: None,
        }
    }

    /// This request, filtered by `term`.
    ///
    /// Chains onto [`first`](Self::first) / [`new`](Self::new):
    /// `PageRequest::first(50).search("ada")`. An empty or whitespace-only
    /// `term` clears the filter rather than setting a blank one.
    pub fn search(mut self, term: impl Into<String>) -> Self {
        let term = term.into();
        self.search = normalize_search(&term).map(str::to_owned);
        self
    }

    /// The query parameters this request contributes.
    ///
    /// `limit` is omitted entirely when unset, rather than sent as `0` — the
    /// server reads `limit=0` as "none", which would return an empty page.
    /// `search` is omitted when unset **and** when blank, so an unfiltered read
    /// and a read whose box was cleared are the same request on the wire.
    pub(crate) fn query(&self) -> Vec<(&'static str, String)> {
        let mut q = vec![("offset", self.offset.to_string())];
        if let Some(limit) = self.limit {
            q.push(("limit", limit.to_string()));
        }
        if let Some(term) = self.search.as_deref().and_then(normalize_search) {
            q.push(("search", term.to_string()));
        }
        q
    }

    /// The request for the page after `page`, or `None` at the end of the set.
    fn after<T>(&self, page: &Page<T>) -> Option<Self> {
        let next = page.offset.saturating_add(page.items.len() as u64);
        // An empty page ends the walk even when `total` claims more: a server
        // that keeps answering with no items would otherwise loop forever.
        if page.items.is_empty() || next >= page.total {
            return None;
        }
        Some(Self {
            offset: next,
            limit: self.limit,
            // Carried, not dropped: §27.4 rule 4. A walk that filtered only its
            // first request would concatenate the matches with the unfiltered
            // remainder, which reads as a server bug from the caller's side.
            search: self.search.clone(),
        })
    }
}

/// The trimmed term, or `None` when there is nothing to filter on.
///
/// Mirrors the server's own normalisation minus the length cap, which is the
/// server's to apply — see [`PageRequest::search`].
fn normalize_search(term: &str) -> Option<&str> {
    let trimmed = term.trim();
    (!trimmed.is_empty()).then_some(trimmed)
}

/// One page of a paginated management read.
///
/// `total` is the size of the whole set, not of `items` — it is the field that
/// tells a caller whether there is more, and the reason §27.4 rule 4 forbids
/// returning a bare `Vec` here.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct Page<T> {
    /// The items on this page.
    pub items: Vec<T>,
    /// How many items exist in the whole set, across every page.
    pub total: u64,
    /// The offset this page starts at.
    pub offset: u64,
    /// The page size the server applied.
    pub limit: u64,
}

impl<T> Page<T> {
    /// Whether another page follows this one.
    pub fn has_more(&self) -> bool {
        !self.items.is_empty() && self.offset.saturating_add(self.items.len() as u64) < self.total
    }
}

/// Walks a paginated read to exhaustion, concatenating every page.
///
/// This is the `list_all` shape §27.4 rule 4 requires. It is a free function
/// rather than a method on [`Page`] because the page cannot fetch its own
/// successor — the operation that produced it can, and each generated `list`
/// hands that operation in as `fetch`.
///
/// The walk stops on an empty page even when `total` disagrees, so a
/// misreporting server costs one wasted request rather than an infinite loop.
pub(crate) async fn collect_pages<T, F, Fut>(
    start: PageRequest,
    mut fetch: F,
) -> Result<Vec<T>, AxiamError>
where
    F: FnMut(PageRequest) -> Fut,
    Fut: std::future::Future<Output = Result<Page<T>, AxiamError>>,
{
    let mut request = start;
    let mut out = Vec::new();
    loop {
        let page = fetch(request.clone()).await?;
        let next = request.after(&page);
        out.extend(page.items);
        match next {
            Some(n) => request = n,
            None => return Ok(out),
        }
    }
}
