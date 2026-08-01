//! Port of `dnfile/types.py`, the name model.
//!
//! Every .NET rule matches on the strings these two types render, so their
//! `Display` output must be byte-for-byte identical to Python `str(DnType)` /
//! `str(DnUnmanagedMethod)`.

use crate::features::Access;

/// A managed type, method, property or field name, resolved from CLR
/// metadata. `class` holds the (possibly nested) class-name chain
/// outermost-first, e.g. `["Outer", "Inner"]` for a nested class.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DnType {
    pub token: u32,
    pub access: Option<Access>,
    pub namespace: String,
    pub class: Vec<String>,
    pub member: String,
}

impl DnType {
    /// `types.py DnType.__init__`: `.ctor`/`.cctor` members are renamed to
    /// drop the leading dot (matches how rules reference constructors).
    pub fn new(
        token: u32,
        class: Vec<String>,
        namespace: String,
        member: String,
        access: Option<Access>,
    ) -> Self {
        let member = match member.as_str() {
            ".ctor" => "ctor".to_string(),
            ".cctor" => "cctor".to_string(),
            _ => member,
        };
        Self {
            token,
            access,
            namespace,
            class,
            member,
        }
    }

    /// `types.py DnType.format_name`. A single-element `class` joins to
    /// itself regardless of separator, so `"/".join` covers both of
    /// upstream's `len(class_) > 1` branches.
    pub fn format_name(class: &[String], namespace: &str, member: &str) -> String {
        let class_str = class.join("/");
        let mut name = if member.is_empty() {
            class_str
        } else {
            format!("{class_str}::{member}")
        };
        if !namespace.is_empty() {
            name = format!("{namespace}.{name}");
        }
        name
    }
}

impl std::fmt::Display for DnType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            DnType::format_name(&self.class, &self.namespace, &self.member)
        )
    }
}

/// An unmanaged (PInvoke) import: `module.method`, e.g. `kernel32.CreateFileA`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DnUnmanagedMethod {
    pub token: u32,
    pub module: String,
    pub method: String,
}

impl DnUnmanagedMethod {
    pub fn new(token: u32, module: String, method: String) -> Self {
        Self {
            token,
            module,
            method,
        }
    }

    /// `types.py DnUnmanagedMethod.format_name`.
    pub fn format_name(module: &str, method: &str) -> String {
        format!("{module}.{method}")
    }
}

impl std::fmt::Display for DnUnmanagedMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            DnUnmanagedMethod::format_name(&self.module, &self.method)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ctor_member_drops_leading_dot() {
        let t = DnType::new(
            1,
            vec!["Foo".to_string()],
            String::new(),
            ".ctor".to_string(),
            None,
        );
        assert_eq!(t.member, "ctor");
        assert_eq!(t.to_string(), "Foo::ctor");
    }

    #[test]
    fn cctor_member_drops_leading_dot() {
        let t = DnType::new(
            1,
            vec!["Foo".to_string()],
            String::new(),
            ".cctor".to_string(),
            None,
        );
        assert_eq!(t.member, "cctor");
    }

    #[test]
    fn nested_class_joins_with_slash() {
        let t = DnType::new(
            1,
            vec!["Outer".to_string(), "Inner".to_string()],
            "System.IO".to_string(),
            "Read".to_string(),
            None,
        );
        assert_eq!(t.to_string(), "System.IO.Outer/Inner::Read");
    }

    #[test]
    fn type_only_has_no_double_colon() {
        let t = DnType::new(
            1,
            vec!["Foo".to_string()],
            "NS".to_string(),
            String::new(),
            None,
        );
        assert_eq!(t.to_string(), "NS.Foo");
    }

    #[test]
    fn unmanaged_method_display() {
        let m = DnUnmanagedMethod::new(1, "kernel32".to_string(), "CreateFileA".to_string());
        assert_eq!(m.to_string(), "kernel32.CreateFileA");
    }
}
