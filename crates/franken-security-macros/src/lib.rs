use proc_macro::TokenStream;
use quote::quote;
use syn::parse::{Parse, ParseStream};
use syn::punctuated::Punctuated;
use syn::{parse_macro_input, Expr, LitStr, Result, Token};

struct SecureHashArgs {
    domain_tag: LitStr,
    fields: Punctuated<Expr, Token![,]>,
}

impl Parse for SecureHashArgs {
    fn parse(input: ParseStream<'_>) -> Result<Self> {
        let domain_tag = input.parse()?;
        input.parse::<Token![,]>()?;
        let fields = Punctuated::parse_terminated(input)?;
        Ok(Self { domain_tag, fields })
    }
}

#[proc_macro]
pub fn secure_hash(input: TokenStream) -> TokenStream {
    let SecureHashArgs { domain_tag, fields } = parse_macro_input!(input as SecureHashArgs);
    let fields = fields.iter();

    quote!({
        let mut hasher = <::sha2::Sha256 as ::sha2::Digest>::new();
        ::sha2::Digest::update(&mut hasher, (#domain_tag).as_bytes());
        #(
            let field_bytes = #fields;
            let field_len = u64::try_from(field_bytes.len()).unwrap_or(u64::MAX);
            ::sha2::Digest::update(&mut hasher, field_len.to_le_bytes());
            ::sha2::Digest::update(&mut hasher, field_bytes);
        )*
        ::hex::encode(::sha2::Digest::finalize(hasher))
    })
    .into()
}
