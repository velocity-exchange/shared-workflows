#!/usr/bin/env python3
"""Print the packages a lockfile records, together with where each is fetched from.

Supports bun.lock, yarn.lock (v1 classic and berry), pnpm-lock.yaml, Cargo.lock and
uv.lock. Parses text only: never installs, never resolves, never reaches the network,
so it is safe to run against a lockfile taken from an untrusted pull request.

  lockfile_packages.py <lockfile>            "<name>\\t<source>", one line per source
  lockfile_packages.py <base> <head>         what <head> adds, one finding per line:
      new     <name>  <source>   the name is absent from the base lockfile
      source  <name>  <source>   the name is present, but fetched from somewhere new
  lockfile_packages.py --digest <findings>   sign-off digest of a findings file

Why the source is compared and not just the name
------------------------------------------------
Comparing names alone is not enough. Repointing an existing package at a tarball, a
git remote, a local path or a different registry leaves its name untouched, so a
name-only diff reports nothing while the bytes that get installed change completely.

What "source" means here is deliberately narrow: it is the *origin* of the bytes, not
their content. A download from a registry collapses to that registry's base, with the
package version dropped, so an ordinary version bump is silent. Any change of
protocol, host or path is reported.

The *resolved* revision is dropped too, and only the resolved one: a URL "#fragment",
which is where a lockfile records the commit it settled on. What a dependency declares
it wants is kept. For a git dependency that means "git+https://host/repo?branch=main"
stays silent as the branch advances, because nothing the repository asked for changed,
while repointing it at "?rev=<some commit>" is reported, because someone deliberately
chose a different commit. That is the split worth having: the mechanical bump is quiet
and the deliberate change is surfaced.

Registry downloads are recognised structurally, by the "<name>/-/<file>" path layout
that every npm-compatible registry serves, rather than by matching a list of known
hostnames. A hostname allowlist would classify every single entry in a repository that
installs from a private registry (Artifactory, GitHub Packages, Verdaccio) as a
non-registry source, so every routine version bump would raise a finding. A gate that
cries wolf on every bump gets its label applied without being read.

The deliberate limit of all this: the gate reports a change of origin, not a change of
content within one origin. A new release from the same registry, or a new commit on
the same git remote, is out of scope by design, and the same boundary is applied on
every side so the behaviour is predictable.

A lockfile that cannot be parsed is a hard error, never an empty result. This runs as
a merge gate, and "unparseable" must never be read as "nothing was added".
"""

import hashlib
import json
import re
import sys
from pathlib import Path

DEFAULT_REGISTRY = "registry:default"

# How many hex characters of the sha256 the sign-off digest keeps. Sign-off is bound to
# this value, so it has to survive a second-preimage search by someone who can pick
# package names freely; 96 bits does, and stays short enough to read in a comment.
DIGEST_LENGTH = 24

_PROTOCOLS = (
    "npm", "patch", "workspace", "file", "link", "portal", "git", r"git\+[a-z]+",
    "https?", "ssh", "exec", "virtual", "alias", "github",
)
# A locator's protocol, as in "pkg@npm:..." or "pkg@patch:...".
_PROTOCOL = re.compile(r"@(?:" + "|".join(_PROTOCOLS) + r"):")
# A reference starting with one of these is not a plain registry version.
_REF_PROTOCOL = re.compile(r"^(?:" + "|".join(_PROTOCOLS) + r"):")
# A semver, or a range that resolves to one. Anything else after "npm:" names a
# different package, which makes it an alias.
_VERSIONISH = re.compile(r"^[\^~><=v\s]*\d")
# The download path every npm-compatible registry serves: "<base>/<name>/-/<file>".
# The captured base is the registry, so the version in the filename drops out.
_REGISTRY_PATH = re.compile(r"^(.*?)/(?:@[^/]+/)?[^/]+/-/[^/]+$")
# Package names and sources are attacker-controlled text that ends up in a
# tab-separated record. A tab or a newline inside one would forge or split a finding.
_UNSAFE = re.compile(r"[\x00-\x1f\x7f]")


def _clean(value):
    """Keep one finding on one line, whatever the lockfile put in the name."""
    return _UNSAFE.sub(lambda m: "\\x%02x" % ord(m.group()), value)


def split_name(spec):
    """'@scope/pkg@1.2.3' -> '@scope/pkg';  'pkg@npm:@other/pkg@^1' -> 'pkg'."""
    spec = spec.split("(", 1)[0]  # drop a pnpm peer suffix
    proto = _PROTOCOL.search(spec)
    if proto and proto.start() > 0:
        return spec[: proto.start()]
    at = spec.rfind("@")
    return spec[:at] if at > 0 else spec


def split_ref(locator):
    """'@scope/pkg@1.2.3' -> ('@scope/pkg', '1.2.3')."""
    name = split_name(locator)
    rest = locator[len(name):]
    return name, rest[1:] if rest.startswith("@") else ""


def _registry(base):
    return f"registry:{base.rstrip('/')}" if base else DEFAULT_REGISTRY


def source_of(ref, registry=""):
    """Classify where a package is fetched from, ignoring its version."""
    if ref.startswith("npm:"):
        target = ref[4:]
        # An ordinary registry dependency is written "pkg@npm:1.2.3"; an alias names a
        # different package instead, as in "pkg@npm:other-pkg@1.2.3".
        if _VERSIONISH.match(target):
            return _registry(registry)
        return f"npm-alias:{split_name(target)}"
    if _REF_PROTOCOL.match(ref):
        if ref.startswith(("http://", "https://")):
            return source_of_url(ref)
        return ref.split("#", 1)[0]
    return _registry(registry)


def source_of_url(url):
    """Classify a download URL: a registry download collapses to the registry base."""
    url = url.split("#", 1)[0]
    match = _REGISTRY_PATH.match(url)
    return _registry(match.group(1)) if match else url


def _put(out, name, source):
    out.setdefault(_clean(name), set()).add(_clean(source))


def _add(out, locator, registry="", source=None):
    name, ref = split_ref(locator)
    _put(out, name, source if source is not None else source_of(ref, registry))


def _strip_jsonc(text):
    """Drop comments and trailing commas so json can load a JSONC document."""
    out = []
    i, n = 0, len(text)
    while i < n:
        char = text[i]
        if char == '"':
            j = i + 1
            while j < n:
                if text[j] == "\\":
                    j += 2
                    continue
                if text[j] == '"':
                    break
                j += 1
            out.append(text[i:j + 1])
            i = j + 1
        elif char == "/" and i + 1 < n and text[i + 1] in "/*":
            if text[i + 1] == "/":
                end = text.find("\n", i)
            else:
                end = text.find("*/", i + 2)
                end = -1 if end == -1 else end + 2
            i = n if end == -1 else end
        elif char == ",":
            j = i + 1
            while j < n and text[j].isspace():
                j += 1
            if not (j < n and text[j] in "]}"):
                out.append(char)
            i += 1
        else:
            out.append(char)
            i += 1
    return "".join(out)


def bun(text, path="<bun.lock>"):
    """bun.lock: "packages": { "<key>": ["<name>@<ref>", "<registry>", {...}, "<hash>"] }

    Parsed as the JSONC document bun itself reads, not scanned line by line, so what
    the gate sees is what bun installs: reformatting the file to hide an entry from a
    line-anchored pattern cannot work. The key is not always the package name (a
    hoisted duplicate gets a compound key such as "anchor-bankrun/@coral-xyz/anchor"),
    so the name comes from the array's own first element. The registry slot is empty
    for the default registry, and absent for non-registry sources where the protocol
    in the locator already identifies the origin.
    """
    data = json.loads(_strip_jsonc(text))
    if not isinstance(data, dict):
        sys.exit(f"{path}: top level is not an object")
    packages = data.get("packages", {})
    if not isinstance(packages, dict):
        sys.exit(f"{path}: 'packages' is not an object")
    out = {}
    for key, entry in packages.items():
        if not isinstance(entry, list) or not entry or not isinstance(entry[0], str):
            sys.exit(f"{path}: unexpected entry for {key!r}: {entry!r}")
        registry = entry[1] if len(entry) > 1 and isinstance(entry[1], str) else ""
        _add(out, entry[0], registry)
    # A lockfile recording no packages while its workspaces still declare some is not
    # an empty project, it is a lockfile that has been emptied.
    declared = _bun_declared(data)
    if declared and not out:
        sys.exit(f"{path}: workspaces declare {declared} dependencies "
                 f"but no packages are recorded")
    return out


def _bun_declared(data):
    total = 0
    workspaces = data.get("workspaces")
    if isinstance(workspaces, dict):
        for workspace in workspaces.values():
            if not isinstance(workspace, dict):
                continue
            for field in ("dependencies", "devDependencies",
                          "optionalDependencies", "peerDependencies"):
                block = workspace.get(field)
                if isinstance(block, dict):
                    total += len(block)
    return total


def yarn(text, path="<yarn.lock>"):
    out = {}
    if "__metadata:" in text:  # berry, v2 and later
        for match in re.finditer(r'^\s+resolution:\s*"([^"]+)"', text, re.M):
            _add(out, match.group(1))
        if not out:
            sys.exit(f"{path}: berry lockfile with no resolution entries")
        return out

    # v1 classic: comma-separated descriptor headers, then a "resolved" download URL.
    # A header carries a range rather than a version, so where a registry entry really
    # comes from is only visible in the URL. The range-derived value is a placeholder
    # that keeps the name recorded even if the URL is missing, and is replaced once the
    # URL is read so a single entry does not report two sources.
    descriptors = []
    placeholders = set()
    for line in text.splitlines():
        stripped = line.strip()
        if line and not line[0].isspace() and not stripped.startswith("#") \
                and stripped.endswith(":"):
            descriptors = [s.strip().strip('"') for s in stripped[:-1].split(", ") if s.strip()]
            for spec in descriptors:
                name, ref = split_ref(spec)
                if _REF_PROTOCOL.match(ref):
                    _put(out, name, source_of(ref))
                else:
                    _put(out, name, DEFAULT_REGISTRY)
                    placeholders.add(_clean(name))
        elif stripped.startswith("resolved "):
            url = stripped.split(" ", 1)[1].strip().strip('"')
            for spec in descriptors:
                name, ref = split_ref(spec)
                if _REF_PROTOCOL.match(ref):
                    continue  # a protocol descriptor is already its own source
                name = _clean(name)
                if name in placeholders:
                    out[name].discard(DEFAULT_REGISTRY)
                    placeholders.discard(name)
                _put(out, name, source_of_url(url))
    if not out and text.strip() and "yarn lockfile" not in text:
        sys.exit(f"{path}: no entries and no yarn lockfile header")
    return out


def pnpm(text, path="<pnpm-lock.yaml>"):
    """pnpm v9 "packages:"/"snapshots:" keys, plus the legacy v5/v6 slash form.

    The key carries a non-registry spec verbatim ("pkg@https://host/x.tgz"), and the
    resolution block beneath it records a tarball or git override that the key does
    not always show, so both are read.
    """
    if "lockfileVersion" not in text:
        sys.exit(f"{path}: no 'lockfileVersion' key; not a pnpm-lock.yaml")
    out = {}
    lines = text.splitlines()
    for index, line in enumerate(lines):
        # The legacy v5/v6 form is checked first: "/@scope/pkg/1.2.3" also matches the
        # v9 pattern below, where it would parse as a locator whose name is "/".
        legacy = re.match(r"^  /((?:@[^/\s]+/)?[^/\s]+)/\d", line)
        if legacy:
            _put(out, legacy.group(1), _pnpm_resolution(lines, index) or DEFAULT_REGISTRY)
            continue
        entry = re.match(r"^  '?([^'\s:][^'\s]*?)'?:\s*$", line)
        if entry:
            spec = entry.group(1)
            if spec.startswith("/") or "@" not in spec.lstrip("@"):
                continue
            name, ref = split_ref(spec)
            _put(out, name, _pnpm_resolution(lines, index) or source_of(ref))
    return out


def _pnpm_resolution(lines, start):
    """Read the resolution block belonging to the entry starting at `start`."""
    for line in lines[start + 1:start + 8]:
        if line.strip() and not line.startswith("    "):
            break  # left this entry's block
        block = re.match(r"^\s+resolution:\s*\{(.*)\}\s*$", line)
        if not block:
            continue
        fields = {k: v.strip().strip("'\"")
                  for k, v in re.findall(r"([\w-]+):\s*([^,}]+)", block.group(1))}
        if "tarball" in fields:
            return source_of_url(fields["tarball"])
        if fields.get("type") == "git":
            return "git:" + fields.get("repo", "unknown").split("#", 1)[0]
        if "directory" in fields:
            return "directory:" + fields["directory"]
        if "integrity" in fields:
            return DEFAULT_REGISTRY
    return None


def _toml_blocks(text, path, kind):
    """Yield (name, block) for each [[package]] in a Cargo.lock or uv.lock."""
    if "[[package]]" not in text:
        if re.search(r"^version = \d+\s*$", text, re.M):
            return  # a well-formed lockfile that records no packages
        sys.exit(f"{path}: no [[package]] block and no version header; not a {kind}")
    for block in text.split("[[package]]")[1:]:
        # Stop at the next table header so a [package.metadata] section, whose
        # requires-dist entries also mention names, cannot be read as this package.
        block = re.split(r"\n(?=\[)", block, maxsplit=1)[0]
        name = re.search(r'^name = "([^"]+)"$', block, re.M)
        if name is None:
            sys.exit(f"{path}: a [[package]] block records no name")
        yield name.group(1), block


def cargo(text, path="<Cargo.lock>"):
    out = {}
    for name, block in _toml_blocks(text, path, "Cargo.lock"):
        source = re.search(r'^source = "([^"]+)"$', block, re.M)
        # No source line means a path dependency inside this workspace.
        _put(out, name, source.group(1).split("#", 1)[0] if source else "path")
    return out


# uv records the source as an inline table: { registry = "..." }, { git = "..." },
# { url = "..." }, { path = "..." }, { editable = "..." } or { virtual = "..." }.
_UV_SOURCE = re.compile(r'^source = \{\s*([\w-]+)\s*=\s*"([^"]*)"', re.M)


def uv(text, path="<uv.lock>"):
    out = {}
    for name, block in _toml_blocks(text, path, "uv.lock"):
        source = _UV_SOURCE.search(block)
        if source is None:
            # uv always writes a source. Naming the gap is better than assuming one,
            # because a source that later appears will then read as a change.
            _put(out, name, "unspecified")
            continue
        kind, value = source.group(1), source.group(2).split("#", 1)[0]
        _put(out, name, _registry(value) if kind == "registry" else f"{kind}:{value}")
    return out


PARSERS = {
    "bun.lock": bun,
    "yarn.lock": yarn,
    "pnpm-lock.yaml": pnpm,
    "Cargo.lock": cargo,
    "uv.lock": uv,
}

SUPPORTED = ", ".join(sorted(PARSERS))


def extract(path):
    """Map every package name in `path` to the set of sources it is fetched from."""
    lockfile = Path(path)
    parser = PARSERS.get(lockfile.name)
    if parser is None:
        sys.exit(f"unsupported lockfile: {lockfile.name} (supported: {SUPPORTED})")
    if not lockfile.exists():  # added by this change, so everything in it is new
        return {}
    text = lockfile.read_text(encoding="utf-8", errors="replace")
    try:
        return parser(text, str(lockfile))
    except SystemExit:
        raise
    except Exception as exc:  # a crash must never read as "nothing was added"
        sys.exit(f"{path}: could not parse as {lockfile.name}: "
                 f"{exc.__class__.__name__}: {exc}")


def diff(base, head):
    """Yield (change, name, source) for everything `head` adds over `base`."""
    for name in sorted(head):
        if name not in base:
            for source in sorted(head[name]):
                yield "new", name, source
        else:
            for source in sorted(head[name] - base[name]):
                yield "source", name, source


def digest(lines):
    """Order-independent digest of a finding set, used to bind sign-off to it."""
    body = "\n".join(sorted(line.strip("\n") for line in lines if line.strip()))
    return hashlib.sha256(body.encode()).hexdigest()[:DIGEST_LENGTH]


def main(argv):
    if len(argv) == 3 and argv[1] == "--digest":
        print(digest(Path(argv[2]).read_text(encoding="utf-8").splitlines()))
    elif len(argv) == 2:
        for name, sources in sorted(extract(argv[1]).items()):
            for source in sorted(sources):
                print(f"{name}\t{source}")
    elif len(argv) == 3:
        for row in diff(extract(argv[1]), extract(argv[2])):
            print("\t".join(row))
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main(sys.argv)
