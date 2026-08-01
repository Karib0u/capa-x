//! Port of the name-resolution half of `dnfile/helpers.py`, the name model.
//!
//! Builds `DnType`/`DnUnmanagedMethod` values for every managed type, managed
//! import, managed method, field and unmanaged (PInvoke) import in a parsed
//! `dnfile::DnPe`. CIL decoding (which *uses* these names to render `api`/
//! `property`/`namespace`/`class` features) is task 3-4's job, not this
//! module's.
//!
//! Ported field-for-field from pinned Python `dnfile`/capa -- including one
//! upstream quirk that must survive intact for parity (see
//! `get_table_row_by_rid` below).

use std::collections::HashMap;

use dnfile::stream::meta_data_tables::mdtables::{
    self as mdtable, table_name_2_index, MDTableRowTrait,
};
use dnfile::ClrData;

use super::types::{DnType, DnUnmanagedMethod};
use super::ExtractError;
use crate::features::Access;

fn parse_err(e: dnfile::error::Error) -> ExtractError {
    ExtractError::Parse(e.to_string())
}

/// `helpers.py calculate_dotnet_token_value`: `(table & 0xFF) << 24 | (rid & 0xFFFFFF)`.
/// `Token.TABLE_SHIFT`/`Token.RID_MASK` (dncil `clr/token.py`).
fn calculate_token_value(table: usize, rid: usize) -> u32 {
    ((table as u32) & 0xFF) << 24 | (rid as u32 & 0x00FF_FFFF)
}

/// `helpers.py is_dotnet_mixed_mode`: a mixed-mode assembly is one whose CLR
/// header does *not* set the IL-only flag.
pub fn is_mixed_mode(net: &ClrData<'_>) -> bool {
    !net.flags.contains(&dnfile::ClrHeaderFlags::IlOnly)
}

/// `helpers.py get_dotnet_table_row`: deliberately reproduces an upstream
/// off-by-one -- `row_index - 1 <= 0` rejects `row_index == 1` (the table's
/// *first* row) as if it were a null reference, not just `row_index == 0`.
/// This is the pinned behavioral spec (AGENTS.md: "Python capa ... wins"),
/// and `resolve_nested_typedef_name`/`resolve_nested_typeref_name` both walk
/// their chains through this exact helper upstream, so silently "fixing" it
/// here would be a silent divergence, not an improvement.
fn get_table_row_by_rid<'p, T>(
    net: &'p ClrData<'p>,
    table_name: &'static str,
    rid: usize,
) -> Option<&'p T>
where
    T: MDTableRowTrait + 'static,
{
    if rid <= 1 {
        return None;
    }
    let table = net.md_table(table_name).ok()?;
    table.row::<T>(rid - 1).ok()
}

/// `helpers.py get_dotnet_nested_class_table_index`: nested RID -> enclosing RID.
fn nested_class_table(net: &ClrData<'_>) -> Result<HashMap<usize, usize>, ExtractError> {
    let mut map = HashMap::new();
    let Ok(table) = net.md_table("NestedClass") else {
        return Ok(map);
    };
    for i in 0..table.row_count() {
        let row = table.row::<mdtable::NestedClass>(i).map_err(parse_err)?;
        map.insert(
            row.nested_class_row_index(),
            row.enclosing_class_row_index(),
        );
    }
    Ok(map)
}

/// `helpers.py resolve_nested_typedef_name`. `typedef`/`rid` come from the
/// caller's own (unbuggy) row iteration; only the enclosing-class chain walk
/// goes through `get_table_row_by_rid`'s buggy lookup, matching upstream.
fn resolve_nested_typedef_name(
    net: &ClrData<'_>,
    nested: &HashMap<usize, usize>,
    rid: usize,
    typedef: &mdtable::TypeDef,
) -> (String, Vec<String>) {
    let Some(&first) = nested.get(&rid) else {
        return (
            typedef.type_namespace.clone(),
            vec![typedef.type_name.clone()],
        );
    };

    let mut names = vec![typedef.type_name.clone()];
    let mut cursor = first;
    loop {
        if !nested.contains_key(&cursor) {
            break;
        }
        let Some(row) = get_table_row_by_rid::<mdtable::TypeDef>(net, "TypeDef", cursor) else {
            names.reverse();
            return (typedef.type_namespace.clone(), names);
        };
        names.push(row.type_name.clone());
        cursor = match nested.get(&cursor) {
            Some(&next) => next,
            None => break,
        };
    }

    let Some(row) = get_table_row_by_rid::<mdtable::TypeDef>(net, "TypeDef", cursor) else {
        names.reverse();
        return (typedef.type_namespace.clone(), names);
    };
    names.push(row.type_name.clone());
    names.reverse();
    (row.type_namespace.clone(), names)
}

/// `helpers.py resolve_nested_typeref_name`. `typeref` is the caller's own
/// (unbuggy) resolution of the coded index; `rid` is that coded index's raw
/// `row_index`. The chain walk itself goes through `get_table_row_by_rid`.
fn resolve_nested_typeref_name(
    net: &ClrData<'_>,
    rid: usize,
    typeref: &mdtable::TypeRef,
) -> (String, Vec<String>) {
    if typeref.resolution_scope.table != "TypeRef" {
        return (
            typeref.type_namespace.clone(),
            vec![typeref.type_name.clone()],
        );
    }

    let Some(mut row) = get_table_row_by_rid::<mdtable::TypeRef>(net, "TypeRef", rid) else {
        return (
            typeref.type_namespace.clone(),
            vec![typeref.type_name.clone()],
        );
    };

    let mut names = Vec::new();
    let mut name = typeref.type_name.clone();
    while row.resolution_scope.table == "TypeRef" {
        names.push(name);
        name = row.type_name.clone();
        row = match get_table_row_by_rid::<mdtable::TypeRef>(
            net,
            "TypeRef",
            row.resolution_scope.row_index,
        ) {
            Some(r) => r,
            None => {
                names.reverse();
                return (typeref.type_namespace.clone(), names);
            }
        };
    }
    names.push(row.type_name.clone());
    names.reverse();
    (row.type_namespace.clone(), names)
}

/// `helpers.py get_dotnet_types`: every `TypeDef` then every `TypeRef`, in
/// that order (matches upstream's own iteration order).
pub fn types(net: &ClrData<'_>) -> Result<Vec<DnType>, ExtractError> {
    let nested = nested_class_table(net)?;
    let mut out = Vec::new();

    let typedef_num = table_name_2_index("TypeDef").map_err(parse_err)?;
    if let Ok(table) = net.md_table("TypeDef") {
        for i in 0..table.row_count() {
            let row = table.row::<mdtable::TypeDef>(i).map_err(parse_err)?;
            let rid = i + 1;
            let (namespace, class) = resolve_nested_typedef_name(net, &nested, rid, row);
            out.push(DnType::new(
                calculate_token_value(typedef_num, rid),
                class,
                namespace,
                String::new(),
                None,
            ));
        }
    }

    let typeref_num = table_name_2_index("TypeRef").map_err(parse_err)?;
    if let Ok(table) = net.md_table("TypeRef") {
        for i in 0..table.row_count() {
            let row = table.row::<mdtable::TypeRef>(i).map_err(parse_err)?;
            let rid = i + 1;
            let (namespace, class) =
                resolve_nested_typeref_name(net, row.resolution_scope.row_index, row);
            out.push(DnType::new(
                calculate_token_value(typeref_num, rid),
                class,
                namespace,
                String::new(),
                None,
            ));
        }
    }

    Ok(out)
}

/// `helpers.py get_dotnet_managed_imports`: `MemberRef` rows whose `Class`
/// resolves to a `TypeRef` (an import from outside this assembly).
pub fn managed_imports(net: &ClrData<'_>) -> Result<Vec<DnType>, ExtractError> {
    let mut out = Vec::new();
    let Ok(table) = net.md_table("MemberRef") else {
        return Ok(out);
    };
    let member_ref_num = table_name_2_index("MemberRef").map_err(parse_err)?;

    for i in 0..table.row_count() {
        let row = table.row::<mdtable::MemberRef>(i).map_err(parse_err)?;
        if row.class.table != "TypeRef" {
            continue;
        }
        let Ok(typeref_row) = net.resolve_coded_index::<mdtable::TypeRef>(&row.class) else {
            continue;
        };

        let mut member_name = row.name.clone();
        let access = if member_name.starts_with("get_") {
            Some(Access::Read)
        } else if member_name.starts_with("set_") {
            Some(Access::Write)
        } else {
            None
        };
        if access.is_some() {
            member_name = member_name[4..].to_string();
        }

        let (namespace, class) = resolve_nested_typeref_name(net, row.class.row_index, typeref_row);
        let rid = i + 1;
        out.push(DnType::new(
            calculate_token_value(member_ref_num, rid),
            class,
            namespace,
            member_name,
            access,
        ));
    }
    Ok(out)
}

/// `helpers.py get_dotnet_methoddef_property_accessors`: `MethodSemantics`
/// rows associated with a `Property` (not an `Event`), mapping the accessor
/// `MethodDef` token to read/write.
fn methoddef_property_accessors(net: &ClrData<'_>) -> Result<HashMap<u32, Access>, ExtractError> {
    let mut map = HashMap::new();
    let Ok(table) = net.md_table("MethodSemantics") else {
        return Ok(map);
    };
    let methoddef_num = table_name_2_index("MethodDef").map_err(parse_err)?;

    for i in 0..table.row_count() {
        let row = table
            .row::<mdtable::MethodSemantics>(i)
            .map_err(parse_err)?;
        if row.association.row_index == 0 || row.association.table == "Event" {
            continue;
        }
        if row.method.row_index == 0 {
            continue;
        }
        let token = calculate_token_value(methoddef_num, row.method.row_index);
        if row
            .semantics
            .contains(&mdtable::enums::ClrMethodSemanticsAttr::Setter)
        {
            map.insert(token, Access::Write);
        } else if row
            .semantics
            .contains(&mdtable::enums::ClrMethodSemanticsAttr::Getter)
        {
            map.insert(token, Access::Read);
        }
    }
    Ok(map)
}

/// `helpers.py get_dotnet_managed_methods`: every `MethodDef` owned by every
/// `TypeDef`, via each type's `MethodList` run.
pub fn managed_methods(net: &ClrData<'_>) -> Result<Vec<DnType>, ExtractError> {
    let nested = nested_class_table(net)?;
    let accessor_map = methoddef_property_accessors(net)?;
    let methoddef_num = table_name_2_index("MethodDef").map_err(parse_err)?;

    let mut out = Vec::new();
    let Ok(typedef_table) = net.md_table("TypeDef") else {
        return Ok(out);
    };
    let Ok(methoddef_table) = net.md_table("MethodDef") else {
        return Ok(out);
    };

    for i in 0..typedef_table.row_count() {
        let typedef = typedef_table
            .row::<mdtable::TypeDef>(i)
            .map_err(parse_err)?;
        let rid = i + 1;

        for entry in &typedef.method_list {
            if entry.row_index == 0 {
                continue;
            }
            let Some(row_idx) = entry.row_index.checked_sub(1) else {
                continue;
            };
            let Ok(method_row) = methoddef_table.row::<mdtable::MethodDef>(row_idx) else {
                continue;
            };

            let token = calculate_token_value(methoddef_num, entry.row_index);
            let access = accessor_map.get(&token).copied();

            let mut name = method_row.name.clone();
            if name.starts_with("get_") || name.starts_with("set_") {
                name = name[4..].to_string();
            }

            let (namespace, class) = resolve_nested_typedef_name(net, &nested, rid, typedef);
            out.push(DnType::new(token, class, namespace, name, access));
        }
    }
    Ok(out)
}

/// `helpers.py get_dotnet_fields`: every `Field` owned by every `TypeDef`,
/// via each type's `FieldList` run.
pub fn fields(net: &ClrData<'_>) -> Result<Vec<DnType>, ExtractError> {
    let nested = nested_class_table(net)?;
    let field_num = table_name_2_index("Field").map_err(parse_err)?;

    let mut out = Vec::new();
    let Ok(typedef_table) = net.md_table("TypeDef") else {
        return Ok(out);
    };
    let Ok(field_table) = net.md_table("Field") else {
        return Ok(out);
    };

    for i in 0..typedef_table.row_count() {
        let typedef = typedef_table
            .row::<mdtable::TypeDef>(i)
            .map_err(parse_err)?;
        let rid = i + 1;

        for entry in &typedef.field_list {
            if entry.row_index == 0 {
                continue;
            }
            let Some(row_idx) = entry.row_index.checked_sub(1) else {
                continue;
            };
            let Ok(field_row) = field_table.row::<mdtable::Field>(row_idx) else {
                continue;
            };

            let (namespace, class) = resolve_nested_typedef_name(net, &nested, rid, typedef);
            out.push(DnType::new(
                calculate_token_value(field_num, entry.row_index),
                class,
                namespace,
                field_row.name.clone(),
                None,
            ));
        }
    }
    Ok(out)
}

/// `helpers.py get_dotnet_unmanaged_imports`: `ImplMap` rows, i.e. PInvoke
/// (`kernel32.dll` -> `kernel32`) forwarded methods.
pub fn unmanaged_imports(net: &ClrData<'_>) -> Result<Vec<DnUnmanagedMethod>, ExtractError> {
    let mut out = Vec::new();
    let Ok(table) = net.md_table("ImplMap") else {
        return Ok(out);
    };

    for i in 0..table.row_count() {
        let row = table.row::<mdtable::ImplMap>(i).map_err(parse_err)?;

        let mut module = String::new();
        if row.import_scope.row_index != 0 {
            if let Some(row_idx) = row.import_scope.row_index.checked_sub(1) {
                if let Ok(modref_table) = net.md_table("ModuleRef") {
                    if let Ok(modref_row) = modref_table.row::<mdtable::ModuleRef>(row_idx) {
                        module = modref_row.name.clone();
                    }
                }
            }
        }

        if row.member_forwarded.row_index == 0 {
            continue;
        }
        let Ok(member_forward_num) = table_name_2_index(row.member_forwarded.table) else {
            continue;
        };
        let token = calculate_token_value(member_forward_num, row.member_forwarded.row_index);

        // like Kernel32.dll -> kernel32
        if let Some(dot) = module.find('.') {
            module.truncate(dot);
        }

        out.push(DnUnmanagedMethod::new(
            token,
            module,
            row.import_name.clone(),
        ));
    }
    Ok(out)
}
