<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/assets/mechub-mark.svg">
    <img src="docs/assets/mechub-mark-light.svg" width="72" alt="mechub mark">
  </picture>
</p>

<h1 align="center">rustproxmoxmcp</h1>

<p align="center"><strong>One Rust MCP server for many Proxmox VE clusters</strong><br>
<em>a mechub project — sovereign network-security automation</em></p>

> **Unofficial / community project.** This is an independent community project and does not claim affiliation with or endorsement by Proxmox Server Solutions GmbH. Product names and trademarks are used only to identify the systems with which the software interoperates.

---

## Status: design pending

**Nothing is implemented yet.** This repository currently reserves the name and
the brand. There is no Cargo workspace, no tool surface, and no architecture
decision that has been made and written down.

Work here is deliberately blocked on
[`mecmcp`](https://github.com/fastrevmd-lab/mecmcp) — the shared Rust crate
family underneath mechub's per-vendor MCP servers. `mecmcp` ships `mecmcp-auth`
today; transport, runtime, inventory, and change control are phases 3–5 of its
program plan. Starting the Proxmox server before those land would mean copying
the entire security layer out of
[`rustpanosmcp`](https://github.com/fastrevmd-lab/rustpanosmcp) and deleting it
again later.

Design starts when `mecmcp` is further along.

## The intent

The existing Proxmox MCP deployment runs one server process per endpoint. This
project replaces that with a single binary holding an inventory of clusters —
the same shape as `rustjunosmcp` and `rustpanosmcp`, and for the same reason:
one endpoint, one token store, per-token scoping, and one place where the
guardrails live.

Sibling servers, both already on this foundation:

| | [rustjunosmcp](https://github.com/fastrevmd-lab/rustjunosmcp) | [rustpanosmcp](https://github.com/fastrevmd-lab/rustpanosmcp) | rustproxmoxmcp |
|---|---|---|---|
| Vendor | Juniper Junos / SRX | Palo Alto PAN-OS | Proxmox VE |
| Transport | NETCONF over SSH | HTTPS XML-API | HTTPS REST |
| Status | shipping | shipping | design pending |

Proxmox is the first target in the family that is not a network device, which
makes it a useful third opinion on where the `mecmcp` crate boundaries actually
belong.

## Naming

Repo `rustproxmoxmcp` per the mechub naming rule (lowercase, no dashes). The
binary and crates will take dashes — `rust-proxmoxmcp` — matching
`rustjunosmcp`/`rust-junosmcp` and `rustpanosmcp`/`rust-panosmcp`.

## License

Licensed under [MIT](LICENSE).
