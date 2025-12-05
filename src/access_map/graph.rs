use super::AccessMapResult;

/// Convert an identity map result into a Graphviz DOT representation.
pub fn to_dot(result: &AccessMapResult) -> String {
    let mut out = String::new();
    out.push_str("digraph G {\n  rankdir=LR;\n");

    out.push_str(&format!(
        "  identity [label=\"{} ({})\"];\n",
        result.identity.id, result.identity.access_type
    ));

    for role in &result.roles {
        let safe_role = sanitize(&role.name);
        out.push_str(&format!(
            "  role_{safe} [label=\"{}\"];\n  identity -> role_{safe};\n",
            role.name,
            safe = safe_role
        ));

        for perm in &role.permissions {
            let safe_perm = sanitize(perm);
            out.push_str(&format!(
                "  perm_{safe} [label=\"{}\"];\n  role_{role_safe} -> perm_{safe};\n",
                perm,
                role_safe = safe_role,
                safe = safe_perm
            ));
        }
    }

    for res in &result.resources {
        let safe = sanitize(&res.name);
        out.push_str(&format!(
            "  res_{safe} [label=\"{} ({})\"];\n  identity -> res_{safe};\n",
            res.name,
            res.risk,
            safe = safe
        ));
    }

    out.push_str("}\n");
    out
}

fn sanitize(name: &str) -> String {
    name.chars().map(|c| if c.is_alphanumeric() { c } else { '_' }).collect()
}
