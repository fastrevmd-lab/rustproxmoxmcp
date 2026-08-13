//! The read surface, declared as data.
//!
//! Proxmox's read API is large and uniform, so a read tool is a catalog entry
//! rather than a function: name, HTTP method, path template, and whether it
//! addresses a specific guest. One generic executor in `crate::client` serves
//! all of them, expanding the template through `mecmcp-openapi`, which rejects
//! a parameter that would break a segment rather than sanitising it.
//!
//! Mutating tools are deliberately *not* here. Each needs preconditions a
//! catalog entry cannot express, so each is written as code that takes an
//! [`crate::AuthorizedGuest`].

use crate::selector::GuestType;
use mecmcp_http::Method;

/// One read tool.
#[derive(Debug, Clone, Copy)]
pub struct ReadTool {
    /// MCP tool name.
    pub name: &'static str,
    /// HTTP method.
    pub method: Method,
    /// Path template with `{node}` and `{vmid}` placeholders.
    pub path: &'static str,
    /// Whether the tool addresses one guest and therefore needs resolution.
    pub needs_guest: bool,
    /// One-line MCP description.
    pub description: &'static str,
    /// Guest type filter for tools that query `/cluster/resources`.
    ///
    /// Task 11's executor filters the response to guests of this type when set.
    pub type_filter: Option<GuestType>,
    /// Query parameters to append to the request.
    ///
    /// Task 11's executor appends these as `?key=value` pairs to the request.
    pub query: &'static [(&'static str, &'static str)],
}

/// The complete 0.1 read surface.
pub const READ_TOOLS: &[ReadTool] = &[
    ReadTool {
        name: "get_cluster_status",
        method: Method::Get,
        path: "/api2/json/cluster/status",
        needs_guest: false,
        description: "Cluster quorum and node membership.",
        type_filter: None,
        query: &[],
    },
    ReadTool {
        name: "get_nodes",
        method: Method::Get,
        path: "/api2/json/nodes",
        needs_guest: false,
        description: "All nodes in the cluster with status and resource totals.",
        type_filter: None,
        query: &[],
    },
    ReadTool {
        name: "get_node_status",
        method: Method::Get,
        path: "/api2/json/nodes/{node}/status",
        needs_guest: false,
        description: "Detailed status for one node.",
        type_filter: None,
        query: &[],
    },
    ReadTool {
        name: "get_vms",
        method: Method::Get,
        path: "/api2/json/cluster/resources",
        needs_guest: false,
        description: "All QEMU guests across the cluster, with node, status and tags.",
        type_filter: Some(GuestType::Qemu),
        query: &[],
    },
    ReadTool {
        name: "get_containers",
        method: Method::Get,
        path: "/api2/json/cluster/resources",
        needs_guest: false,
        description: "All LXC guests across the cluster, with node, status and tags.",
        type_filter: Some(GuestType::Lxc),
        query: &[],
    },
    ReadTool {
        name: "get_vm_config",
        method: Method::Get,
        path: "/api2/json/nodes/{node}/qemu/{vmid}/config",
        needs_guest: true,
        description: "Configuration of one QEMU guest, including its Proxmox digest.",
        type_filter: None,
        query: &[],
    },
    ReadTool {
        name: "get_container_config",
        method: Method::Get,
        path: "/api2/json/nodes/{node}/lxc/{vmid}/config",
        needs_guest: true,
        description: "Configuration of one LXC guest, including its Proxmox digest.",
        type_filter: None,
        query: &[],
    },
    // LXC-only: the path hardcodes 'lxc'. Task 11's executor must refuse a QEMU
    // target for this tool rather than issuing a request that can only fail.
    ReadTool {
        name: "get_container_ip",
        method: Method::Get,
        path: "/api2/json/nodes/{node}/lxc/{vmid}/interfaces",
        needs_guest: true,
        description: "Network interfaces and addresses of one LXC guest.",
        type_filter: None,
        query: &[],
    },
    ReadTool {
        name: "get_guest_status",
        method: Method::Get,
        path: "/api2/json/nodes/{node}/{kind}/{vmid}/status/current",
        needs_guest: true,
        description: "Current runtime status of one guest.",
        type_filter: None,
        query: &[],
    },
    ReadTool {
        name: "list_snapshots",
        method: Method::Get,
        path: "/api2/json/nodes/{node}/{kind}/{vmid}/snapshot",
        needs_guest: true,
        description: "Snapshots of one guest.",
        type_filter: None,
        query: &[],
    },
    ReadTool {
        name: "get_storage",
        method: Method::Get,
        path: "/api2/json/nodes/{node}/storage",
        needs_guest: false,
        description: "Storage backends visible to one node, with usage.",
        type_filter: None,
        query: &[],
    },
    ReadTool {
        name: "list_backups",
        method: Method::Get,
        path: "/api2/json/nodes/{node}/storage/{storage}/content",
        needs_guest: false,
        description: "Backup archives on one storage backend.",
        type_filter: None,
        query: &[("content", "backup")],
    },
    ReadTool {
        name: "list_isos",
        method: Method::Get,
        path: "/api2/json/nodes/{node}/storage/{storage}/content",
        needs_guest: false,
        description: "ISO images on one storage backend.",
        type_filter: None,
        query: &[("content", "iso")],
    },
    ReadTool {
        name: "list_templates",
        method: Method::Get,
        path: "/api2/json/nodes/{node}/storage/{storage}/content",
        needs_guest: false,
        description: "Container templates on one storage backend.",
        type_filter: None,
        query: &[("content", "vztmpl")],
    },
    ReadTool {
        name: "list_tasks",
        method: Method::Get,
        path: "/api2/json/nodes/{node}/tasks",
        needs_guest: false,
        description: "Recent tasks on one node.",
        type_filter: None,
        query: &[],
    },
    ReadTool {
        name: "get_task_status",
        method: Method::Get,
        path: "/api2/json/nodes/{node}/tasks/{upid}/status",
        needs_guest: false,
        description: "Status of one task by UPID.",
        type_filter: None,
        query: &[],
    },
];

/// Look up a read tool by MCP name.
#[must_use]
pub fn read_tool(name: &str) -> Option<&'static ReadTool> {
    READ_TOOLS.iter().find(|tool| tool.name == name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tool_names_are_unique() {
        let mut seen = std::collections::BTreeSet::new();
        for tool in READ_TOOLS {
            assert!(seen.insert(tool.name), "duplicate tool {}", tool.name);
        }
    }

    #[test]
    fn guest_scoped_tools_template_both_node_and_vmid() {
        for tool in READ_TOOLS.iter().filter(|tool| tool.needs_guest) {
            assert!(tool.path.contains("{node}"), "{} lacks node", tool.name);
            assert!(tool.path.contains("{vmid}"), "{} lacks vmid", tool.name);
        }
    }

    #[test]
    fn no_path_is_absolute_against_a_different_api_root() {
        for tool in READ_TOOLS {
            assert!(tool.path.starts_with("/api2/json/"), "{} path {}", tool.name, tool.path);
        }
    }

    #[test]
    fn looks_up_by_name() {
        assert!(read_tool("get_vms").is_some());
        assert!(read_tool("not_a_tool").is_none());
    }

    #[test]
    fn the_two_guest_list_tools_are_distinguished_by_type_filter() {
        // Both hit /cluster/resources; without the filter one of them would lie.
        let vms = read_tool("get_vms").expect("get_vms");
        let containers = read_tool("get_containers").expect("get_containers");
        assert_eq!(vms.path, containers.path, "tools should share the same path");
        assert_eq!(vms.type_filter, Some(GuestType::Qemu), "get_vms should filter to QEMU");
        assert_eq!(containers.type_filter, Some(GuestType::Lxc), "get_containers should filter to LXC");
    }

    #[test]
    fn the_three_storage_tools_are_distinguished_by_content_query() {
        let backups = read_tool("list_backups").expect("list_backups");
        let isos = read_tool("list_isos").expect("list_isos");
        let templates = read_tool("list_templates").expect("list_templates");
        assert_eq!(backups.path, isos.path, "backups and isos should share the same path");
        assert_eq!(isos.path, templates.path, "isos and templates should share the same path");
        assert_eq!(backups.query, &[("content", "backup")], "list_backups should filter by backup content");
        assert_eq!(isos.query, &[("content", "iso")], "list_isos should filter by iso content");
        assert_eq!(templates.query, &[("content", "vztmpl")], "list_templates should filter by vztmpl content");
    }

    #[test]
    fn tools_sharing_a_path_always_carry_a_discriminator() {
        // Guards the general defect the two rulings above fixed: if a future entry
        // reuses a path with neither a type filter nor a query, two tools become
        // indistinguishable and at least one of their descriptions is false.
        for (index, tool) in READ_TOOLS.iter().enumerate() {
            for other in READ_TOOLS.iter().skip(index + 1) {
                if tool.path != other.path {
                    continue;
                }
                let distinguished = tool.type_filter != other.type_filter || tool.query != other.query;
                assert!(
                    distinguished,
                    "{} and {} share a path with no discriminator",
                    tool.name, other.name
                );
            }
        }
    }
}
