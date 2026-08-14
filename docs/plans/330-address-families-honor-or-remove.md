# Implementation Plan — Make `ipam.address_families` Actually Do Something

- **Issue:** [datum-cloud/galactic#330](https://github.com/datum-cloud/galactic/issues/330) — "address_families does nothing."
- **Related:** #304 (the refactor that moved the field into the `ipam` block without giving
  it a reader — it was equally dead before that, at the top level, per the issue's own
  comment).
- **Status:** planning only — no implementation started.

## 1. Problem statement

`internal/cniipam/config.go`'s `parseConf` parses, validates, and defaults
`conf.IPAM.AddressFamilies` (defaults to `["ipv6"]` when unset; rejects anything outside
`"ipv6"`/`"ipv4"`). Nothing downstream ever reads the field back. `allocatePool`
(`internal/cniipam/allocate.go`) branches purely on whether `conf.IPv6Subnet`/
`conf.IPv4Subnet` are non-empty; `deallocate`/`checkAllocation` do the same. Repro from the
issue: configure both `ipv6_subnet` and `ipv4_subnet` on an attachment, set
`address_families: ["ipv6"]`, and the pod still gets an IPv4 address — the field is
validated and then discarded.

`docs/cni/configuration.md` makes this worse, not better: it documents the field as
"Families to record as in-use... Validated at parse time — keep this consistent with
which of `ipv6_subnet`/`ipv4_subnet` are set" — i.e. it tells operators to manually keep a
field in sync with other fields it has no actual effect on. That's the "config that
silently does nothing is worse than config that does not exist" the issue calls out.

## 2. Decision: honor it, don't remove it

The issue frames this as a binary choice. Removing it was considered and rejected:

- The field's only plausible real use case — restricting a single attachment to one
  family on a VPC/pool that otherwise has both configured (exactly the issue's own repro)
  — has no other way to express itself today. `ipv6_subnet`/`ipv4_subnet` describe *which
  pools exist*; there's currently no field describing *which of the existing pools this
  particular attachment should draw from*. Deleting `address_families` would delete that
  capability along with the dead code, not just clean up debt.
- The fix is small and self-contained (one function, no new types, no new persisted
  state) — smaller than the diff to strip the field, its validation, its doc-comment,
  its config-doc row and all three worked examples in `docs/cni/configuration.md` that
  already set it.

So: `address_families`, when present, becomes a *restriction* over whichever of
`ipv6_subnet`/`ipv4_subnet` are configured — it can only narrow allocation, never widen it
beyond pools that are actually configured. Omitting it entirely preserves exactly today's
behavior (allocate from whatever pools are configured).

## 3. Where the fix lives: `parseConf`, not `allocate.go`

`parseConf` already fully resolves the effective config before anything else sees it —
it applies `GALACTIC_IPAM_ENABLE_LOCAL_IPAM`'s default-pool-fill the same way. By the time
`conf.IPAM` leaves `parseConf`, its `IPv6Subnet`/`IPv4Subnet` fields already fully
determine mode (per `cniipam.go`'s own package doc comment). Filtering
`AddressFamilies` into those same two fields *inside* `parseConf`, rather than
re-deriving the filter in `allocatePool`, `deallocate`, and `checkAllocation`
separately, keeps that invariant true instead of adding a second, parallel
config-resolution rule three call sites each have to apply consistently.

This also falls out of `cmdAdd`/`cmdDel`/`cmdCheck` (`internal/cniipam/ops.go`) each
calling `parseConf(args.StdinData)` independently, on the same full config document, every
single time (per the CNI IPAM delegation contract) — there's no persisted state to keep in
sync across ADD/DEL/CHECK; each op re-derives the identical filtered result from the same
input. `deallocate`/`checkAllocation`'s existing `effectiveIPv6Subnet` fallback (used to
reconstruct the `GALACTIC_IPAM_ENABLE_LOCAL_IPAM` default pool without re-reading the env
var at DEL/CHECK time) composes with this unchanged, since it also only reads
`conf.IPv6Subnet`/`conf.IPv4Subnet`.

**Alternative considered and rejected:** add the filter as a helper called from
`allocatePool`/`deallocate`/`checkAllocation` individually. Rejected — three call sites
applying one rule invites drift (exactly the kind of "docs say keep it consistent, nothing
enforces it" gap this issue is about), for no benefit over resolving it once.

## 4. The change

`internal/cniipam/config.go`, `parseConf`:

- Delete the unconditional default-fill (`if len(conf.IPAM.AddressFamilies) == 0 {
  conf.IPAM.AddressFamilies = []string{addressFamilyIPv6} }`). An unset field must mean
  "no restriction," not "restricted to IPv6" — the latter would silently break every
  existing dual-stack or IPv4-only config that has never set this field, which is the
  overwhelming majority (`docs/cni/configuration.md`'s own dual-stack and IPv4-only
  examples included).
- Keep the existing per-entry validation (`"ipv6"`/`"ipv4"` only) unchanged.
- After validation, when `AddressFamilies` is non-empty and `StaticIP` is unset (the
  field is meaningless for the single-address static path — `allocate` picks that path
  on `StaticIP` presence alone, unconditionally, regardless of what else is configured):
  clear whichever of `IPv6Subnet`/`IPv4Subnet` names a family not listed.
- If that leaves both `IPv6Subnet` and `IPv4Subnet` empty (every configured pool's family
  was excluded, or the requested family has no pool at all), fail parse with a `types.Error`
  (code 7) naming `address_families` explicitly — the existing generic "ipv6_subnet or
  ipv4_subnet is required" error from `allocatePool` would be confusing here since the
  operator can see they *did* set a subnet field; the actual cause is the family filter.

Sketch:

```go
if conf.IPAM.StaticIP == "" && len(conf.IPAM.AddressFamilies) > 0 {
    var wantIPv6, wantIPv4 bool
    for _, af := range conf.IPAM.AddressFamilies {
        switch af {
        case addressFamilyIPv6:
            wantIPv6 = true
        case addressFamilyIPv4:
            wantIPv4 = true
        }
    }
    if !wantIPv6 {
        conf.IPAM.IPv6Subnet = ""
    }
    if !wantIPv4 {
        conf.IPAM.IPv4Subnet = ""
    }
    if conf.IPAM.IPv6Subnet == "" && conf.IPAM.IPv4Subnet == "" {
        return nil, &types.Error{Code: 7, Msg: fmt.Sprintf(
            "ipam.address_families %v excludes every pool this config configures "+
                "(ipam.ipv6_subnet/ipam.ipv4_subnet)", conf.IPAM.AddressFamilies),
        }
    }
}
```

Placed after the existing per-entry validation loop, before `parseConf`'s `return conf,
nil`. No change to `allocate.go`, `ops.go`, or any other file's control flow —
`allocatePool`'s existing "neither subnet set" error, and `deallocate`/
`checkAllocation`'s existing per-family `if subnet != ""` guards, already do exactly the
right thing once `parseConf` hands them pre-filtered subnets.

One second-order effect worth calling out, not fixing: `internal/cnibgp/bgp.go`'s
`ipamAdvertisementPrefixes` derives which prefixes to advertise from the actual
`IPAMResult` fields (populated or nil), never from `address_families` directly. Since the
fix makes `allocatePool` simply never populate the excluded family's `IPAMResult` field,
the BGP advertisement path is already correct with zero changes — it was always going to
advertise only what was actually allocated.

## 5. Docs update

`docs/cni/configuration.md`'s `address_families` table row: replace "Families to record
as in-use... Defaults to `["ipv6"]`... keep this consistent with which of
`ipv6_subnet`/`ipv4_subnet` are set" with something like: "Restricts allocation to the
listed families, narrowing whichever of `ipv6_subnet`/`ipv4_subnet` are configured on this
attachment (never widens beyond them). Omit for no restriction — allocate from every pool
configured. Rejects a config that excludes every configured pool." The three worked
examples (lines ~336–396) already set it consistently with the subnets they configure, so
none of them need to change.

## 6. Testing

`internal/cniipam/config_test.go` (`TestParseConf` table, plus new dedicated cases):

- Repro case from the issue: both `ipv6_subnet` and `ipv4_subnet` set,
  `address_families: ["ipv6"]` → parsed conf has `IPv4Subnet == ""`, `IPv6Subnet`
  unchanged.
- Symmetric case: `address_families: ["ipv4"]` with both subnets set → `IPv6Subnet ==
  ""`.
- `address_families: ["ipv6", "ipv4"]` with both subnets set → neither cleared
  (dual-stack unaffected).
- No `address_families` at all, both subnets set → neither cleared (default behavior
  for the overwhelmingly common case is unchanged — this is the regression test for "an
  unset field must not mean ipv6-only").
- `address_families: ["ipv4"]` with only `ipv6_subnet` set (no `ipv4_subnet`) → parse
  error naming `address_families`.
- `static_ip` set alongside an `address_families` that would otherwise exclude
  everything → no error, static path untouched (filter skipped entirely when
  `static_ip` is present).

`internal/cniipam/allocate_test.go`: one end-to-end case driving `parseConf` → `allocate`
together (existing tests construct `&IPAM{}` literals directly and bypass `parseConf`,
so this is the one test that actually exercises the full ADD path the issue's repro
describes) — both subnets configured, `address_families: ["ipv6"]`, assert
`res.IPv4Address == nil` and `len(res.Routes) == 1`.

No changes needed to `internal/cnibgp` tests — per §4, that path already derives
correctly from whatever `IPAMResult` actually contains.

## 7. Rollout

Per [[project_galactic_cni_not_production]] (not yet production, breaking config/behavior
changes are fine) there's no back-compat constraint. The only behavior change for configs
that *already* set `address_families` is that it starts actually restricting allocation —
which is the fix, not a regression, and matches every existing example in
`docs/cni/configuration.md` (each already sets it consistent with its own subnets, so none
of them observe any change). Configs that never set it see no change at all, since an
unset field now means "no restriction" instead of secretly defaulting to `["ipv6"]` that
nothing read anyway.

## 8. Open question for review

Should excluding every configured pool be a hard parse error (as designed above), or
should it silently fall through to `allocatePool`'s existing generic "neither subnet set"
error instead of a dedicated message? Leaning toward the dedicated message — it names the
actual cause (`address_families`) rather than making the operator guess why a subnet they
can see is set in the JSON isn't taking effect, which is the exact complaint this issue
raises about the field itself.
