use proc_macro::{Delimiter, Group, Ident, TokenStream, TokenTree};

use core::iter::once;

fn unwrap_paren(tt: Option<TokenTree>, where_: &str) -> proc_macro::Group {
    match tt {
        Some(TokenTree::Group(group)) if group.delimiter() == Delimiter::Parenthesis => {
            group
        }
        _ => panic!("expected {} to be `()`-delimited ", where_)
    }
}

// Generates an impl block where the span of `impl` and `for` is copied from another token.
//
// input: `($($prev_tokens:tt)*) $for_span:tt $($rem:tt)*`
#[doc(hidden)]
#[proc_macro]
pub fn __impl_with_span(input: TokenStream) -> TokenStream {
    let mut iter = input.into_iter();


    let impl_span = match iter.next().expect("expected second token tree to exist") {
        TokenTree::Group(group) if group.delimiter() == Delimiter::None => {
            group.stream().into_iter().next().unwrap().span()
        }
        tt => tt.span()
    };

    let mut out = unwrap_paren(iter.next(), "second token tree (impl attributes)").stream();

    out.extend(once(TokenTree::Ident(Ident::new("impl", impl_span))));

    out.extend(unwrap_paren(iter.next(), "third token tree (impld trait)").stream());

    out.extend(once(TokenTree::Ident(Ident::new("for", impl_span))));

    out.extend(unwrap_paren(iter.next(), "fourth token tree (impld type)").stream());
    
    out.extend(unwrap_paren(iter.next(), "fifth token tree (where clause)").stream());

    {
        let mut group = Group::new(
            Delimiter::Brace,
            unwrap_paren(iter.next(), "sixth token tree (associated items)").stream(),
        );
        group.set_span(group.span().located_at(impl_span));

        out.extend(once(TokenTree::Group(group)));
    }

    out
}