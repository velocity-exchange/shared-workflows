#!/usr/bin/env python3
"""Tests for lockfile_packages.py. Run with: python3 tests/test_parser.py

Plain asserts and no third-party imports, so the suite has no dependencies of
its own. A dependency gate that needed its own dependency tree would be a poor
advertisement for itself.

The tests are the specification for what "source" means. Two properties matter
most, and both are asserted directly below:

  * an ordinary registry version bump produces NO finding, and
  * a change of protocol, host or path DOES produce a `source` finding.

Get the first wrong and every dependency bump raises a finding, reviewers learn
to apply the label without reading, and the gate is worse than nothing.
"""

import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import lockfile_packages as lp  # noqa: E402

PARSER = str(ROOT / "lockfile_packages.py")

failures = []


def show(value):
    if isinstance(value, set):
        return sorted(value)
    if isinstance(value, dict):
        return {k: sorted(v) for k, v in sorted(value.items())}
    return value


def check(label, got, want):
    if got != want:
        failures.append(f"{label}\n     got:  {show(got)}\n     want: {show(want)}")
        print(f"  FAIL  {label}")
    else:
        print(f"  ok    {label}")


def write(name, text):
    path = Path(tempfile.mkdtemp()) / name
    path.write_text(text)
    return path


def run(*args, expect=0):
    done = subprocess.run([sys.executable, PARSER, *[str(a) for a in args]],
                          capture_output=True, text=True)
    if done.returncode != expect:
        failures.append(f"{PARSER} {args} exited {done.returncode}, wanted {expect}\n"
                        f"     stderr: {done.stderr.strip()}")
    return done


def names(mapping):
    return set(mapping)


def findings(base_text, head_text, name="bun.lock"):
    """The findings a change to one lockfile produces, as a sorted list of tuples."""
    base = write(name, base_text)
    head = write(name, head_text)
    return sorted(lp.diff(lp.extract(base), lp.extract(head)))


# --------------------------------------------------------------------------
print("split_name")
check("plain", lp.split_name("pkg@1.2.3"), "pkg")
check("scoped", lp.split_name("@scope/pkg@1.2.3"), "@scope/pkg")
check("yarn alias", lp.split_name("@coral-xyz/anchor-29@npm:@coral-xyz/anchor@0.29.0"),
      "@coral-xyz/anchor-29")
check("yarn patch", lp.split_name("fsevents@patch:fsevents@npm%3A2.3.2"), "fsevents")
check("pnpm peer suffix", lp.split_name("@scope/pkg@1.1.2(react@19.0.0)"), "@scope/pkg")
check("workspace proto", lp.split_name("mypkg@workspace:."), "mypkg")
check("no version at all", lp.split_name("pkg"), "pkg")
check("scoped, no version", lp.split_name("@scope/pkg"), "@scope/pkg")

# --------------------------------------------------------------------------
print("\nsource classification")
check("plain semver is the default registry", lp.source_of("1.2.3"), "registry:default")
check("a range is the default registry", lp.source_of("^1.2.3"), "registry:default")
check("yarn npm: with a version is the registry", lp.source_of("npm:1.2.3"), "registry:default")
check("yarn npm: with a name is an alias",
      lp.source_of("npm:@coral-xyz/anchor@0.29.0"), "npm-alias:@coral-xyz/anchor")
check("a declared registry is recorded",
      lp.source_of("1.2.3", "https://npm.pkg.github.com/"), "registry:https://npm.pkg.github.com")
check("a tarball keeps its whole URL",
      lp.source_of("https://attacker.invalid/evil.tgz"), "https://attacker.invalid/evil.tgz")
check("a git ref drops only the pinned revision",
      lp.source_of("git+https://github.com/o/r.git#deadbeef"), "git+https://github.com/o/r.git")
check("file: is its own source", lp.source_of("file:../local"), "file:../local")
check("workspace: is its own source", lp.source_of("workspace:packages/sdk"), "workspace:packages/sdk")

# Registry downloads are recognised by the npm "<name>/-/<file>" path layout, not by
# a list of known hosts. A host allowlist would report every version bump in any
# repository that installs from a private registry.
check("public npm URL collapses to its base",
      lp.source_of_url("https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz#abc"),
      "registry:https://registry.npmjs.org")
check("scoped npm URL collapses to its base",
      lp.source_of_url("https://registry.yarnpkg.com/@scope/pkg/-/pkg-1.0.0.tgz"),
      "registry:https://registry.yarnpkg.com")
check("a private registry collapses to its own base, so bumps stay quiet",
      lp.source_of_url("https://artifactory.corp/api/npm/npm-remote/lodash/-/lodash-4.17.21.tgz"),
      "registry:https://artifactory.corp/api/npm/npm-remote")
check("a URL with no registry layout keeps its full identity",
      lp.source_of_url("https://attacker.invalid/evil.tgz"), "https://attacker.invalid/evil.tgz")
check("a host swap that mimics the registry layout still changes the source",
      lp.source_of_url("https://evil.example/lodash/-/lodash-4.17.21.tgz"),
      "registry:https://evil.example")

# --------------------------------------------------------------------------
print("\nbun.lock")
BUN = """{
  "lockfileVersion": 1,
  "workspaces": {
    "": { "name": "root", "dependencies": { "two": "^2.0.0" } },
  },
  "packages": {
    "@scope/one": ["@scope/one@1.0.0", "", { "dependencies": {} }, "sha512-a"],

    "two": ["two@2.0.0", "", {}, "sha512-b"],

    "anchor-bankrun/@coral-xyz/anchor": ["@coral-xyz/anchor@0.29.0", "", {}, "sha512-c"],

    "native": ["native@1.0.0", "", { "os": [ "linux" ], "cpu": [ "x64" ] }, "sha512-d"],
  }
}
"""
check("basic + compound key + os/cpu arrays are not packages", names(lp.bun(BUN)),
      {"@scope/one", "two", "@coral-xyz/anchor", "native"})
check("every entry resolves to the default registry",
      lp.bun(BUN)["two"], {"registry:default"})

# bun.lock is JSONC, so whitespace is not significant to bun. An entry appended to an
# existing line installs identically, but a line-anchored regex would never see it.
# Parsing the document the way bun does makes the class of trick impossible.
MERGED = BUN.replace(
    '"two": ["two@2.0.0", "", {}, "sha512-b"],',
    '"two": ["two@2.0.0", "", {}, "sha512-b"], "evil": ["evil@9.9.9", "", {}, "sha512-e"],',
)
check("same-line entry is not missed", names(lp.bun(MERGED)),
      {"@scope/one", "two", "@coral-xyz/anchor", "native", "evil"})
check("comments do not hide an entry",
      names(lp.bun(BUN.replace('"two":', '/* sneaky */ "two":'))),
      {"@scope/one", "two", "@coral-xyz/anchor", "native"})

# --------------------------------------------------------------------------
print("\nthe source-substitution bypass (v1 reported nothing here)")
# Reproduced from velocity-common/bun.lock: rewriting the locator's version to a URL
# keeps the package name, and therefore the name count, completely unchanged.
SUB_BASE = """{
  "lockfileVersion": 1,
  "packages": {
    "husky": ["husky@8.0.3", "", {}, "sha512-a"],
  }
}
"""
SUB_HEAD = SUB_BASE.replace('"husky@8.0.3"', '"husky@https://attacker.invalid/evil.tgz"')
check("the name set is identical, which is why a name-only diff sees nothing",
      names(lp.bun(SUB_BASE)), names(lp.bun(SUB_HEAD)))
check("substituting the source is reported",
      findings(SUB_BASE, SUB_HEAD),
      [("source", "husky", "https://attacker.invalid/evil.tgz")])

print("\nversion bumps stay quiet, origin changes do not")
check("a plain registry version bump produces no finding",
      findings(SUB_BASE, SUB_BASE.replace("husky@8.0.3", "husky@8.0.4")), [])
check("a caret range bump produces no finding",
      findings(SUB_BASE, SUB_BASE.replace('"husky@8.0.3"', '"husky@^9.1.0"')), [])
check("switching to git is reported",
      findings(SUB_BASE, SUB_BASE.replace('"husky@8.0.3"',
                                          '"husky@git+https://github.com/evil/husky.git#abc"')),
      [("source", "husky", "git+https://github.com/evil/husky.git")])
check("switching to a local path is reported",
      findings(SUB_BASE, SUB_BASE.replace('"husky@8.0.3"', '"husky@file:../evil"')),
      [("source", "husky", "file:../evil")])
check("an npm alias to another package is reported",
      findings(SUB_BASE, SUB_BASE.replace('"husky@8.0.3"', '"husky@npm:evil-husky@1.0.0"')),
      [("source", "husky", "npm-alias:evil-husky")])
check("a registry host swap is reported",
      findings(SUB_BASE, SUB_BASE.replace('"husky@8.0.3", ""',
                                          '"husky@8.0.3", "https://evil.example/"')),
      [("source", "husky", "registry:https://evil.example")])
check("a git revision bump inside the same origin is not reported",
      findings(SUB_BASE.replace('"husky@8.0.3"', '"husky@git+https://github.com/o/r.git#aaa"'),
               SUB_BASE.replace('"husky@8.0.3"', '"husky@git+https://github.com/o/r.git#bbb"')),
      [])
check("a brand new package is reported as new, not as a source change",
      findings(SUB_BASE, SUB_BASE.replace(
          '"husky": ["husky@8.0.3", "", {}, "sha512-a"],',
          '"husky": ["husky@8.0.3", "", {}, "sha512-a"],\n    "evil": ["evil@1.0.0", "", {}, "sha512-e"],')),
      [("new", "evil", "registry:default")])

# --------------------------------------------------------------------------
print("\nyarn.lock")
YARN_V1 = """# THIS IS AN AUTOGENERATED FILE.
# yarn lockfile v1


"@scope/one@^1.0.0":
  version "1.0.1"
  resolved "https://registry.yarnpkg.com/@scope/one/-/one-1.0.1.tgz#aaa"

two@^2.0.0, two@^2.1.0:
  version "2.1.0"
  resolved "https://registry.yarnpkg.com/two/-/two-2.1.0.tgz#bbb"

"@coral-xyz/anchor-29@npm:@coral-xyz/anchor@0.29.0":
  version "0.29.0"
  resolved "https://registry.yarnpkg.com/@coral-xyz/anchor/-/anchor-0.29.0.tgz#ccc"

local@file:../local:
  version "0.0.0"
"""
check("v1 classic, incl. multi-descriptor and alias", names(lp.yarn(YARN_V1)),
      {"@scope/one", "two", "@coral-xyz/anchor-29", "local"})
check("v1 takes a registry entry's source from its resolved URL, not its range",
      lp.yarn(YARN_V1)["two"], {"registry:https://registry.yarnpkg.com"})
check("v1 keeps a protocol descriptor as its own source",
      lp.yarn(YARN_V1)["local"], {"file:../local"})
check("v1 registry version bump produces no finding",
      findings(YARN_V1, YARN_V1.replace("two-2.1.0.tgz", "two-2.2.0.tgz")
                               .replace('version "2.1.0"', 'version "2.2.0"'), "yarn.lock"), [])
check("v1 resolved-URL host swap is reported",
      findings(YARN_V1, YARN_V1.replace("https://registry.yarnpkg.com/two/-/two-2.1.0.tgz",
                                        "https://evil.example/two.tgz"), "yarn.lock"),
      [("source", "two", "https://evil.example/two.tgz")])

YARN_BERRY = """__metadata:
  version: 8
  cacheKey: 10c0

"@scope/one@npm:^1.0.0":
  version: 1.0.1
  resolution: "@scope/one@npm:1.0.1"

"fsevents@patch:fsevents@npm%3A2.3.2#optional!builtin":
  version: 2.3.2
  resolution: "fsevents@patch:fsevents@npm%3A2.3.2#optional!builtin<compat/fsevents>"

"root@workspace:.":
  version: 0.0.0-use.local
  resolution: "root@workspace:."
"""
check("berry via resolution lines", names(lp.yarn(YARN_BERRY)),
      {"@scope/one", "fsevents", "root"})
check("berry npm: resolution is the registry",
      lp.yarn(YARN_BERRY)["@scope/one"], {"registry:default"})
check("berry version bump produces no finding",
      findings(YARN_BERRY, YARN_BERRY.replace("npm:1.0.1", "npm:1.0.2"), "yarn.lock"), [])
check("berry switch to a tarball is reported",
      findings(YARN_BERRY,
               YARN_BERRY.replace('"@scope/one@npm:1.0.1"', '"@scope/one@https://evil.example/x.tgz"'),
               "yarn.lock"),
      [("source", "@scope/one", "https://evil.example/x.tgz")])

# --------------------------------------------------------------------------
print("\npnpm-lock.yaml")
PNPM = """lockfileVersion: '9.0'

packages:

  '@scope/one@1.0.0':
    resolution: {integrity: sha512-a}

  two@2.0.0:
    resolution: {integrity: sha512-b}

  three@1.0.0:
    resolution: {tarball: https://evil.example/three.tgz}

snapshots:

  '@scope/one@1.0.0(react@19.0.0)':
    dependencies: {}
"""
check("v9 packages + peer-suffixed snapshots collapse", names(lp.pnpm(PNPM)),
      {"@scope/one", "two", "three"})
check("v9 integrity means the registry", lp.pnpm(PNPM)["two"], {"registry:default"})
check("v9 tarball resolution is read, not ignored",
      lp.pnpm(PNPM)["three"], {"https://evil.example/three.tgz"})
check("v9 version bump produces no finding",
      findings(PNPM, PNPM.replace("two@2.0.0", "two@2.1.0"), "pnpm-lock.yaml"), [])
check("v9 swapping a registry entry for a tarball is reported",
      findings(PNPM, PNPM.replace("    resolution: {integrity: sha512-b}",
                                  "    resolution: {tarball: https://evil.example/two.tgz}"),
               "pnpm-lock.yaml"),
      [("source", "two", "https://evil.example/two.tgz")])

PNPM_LEGACY = """lockfileVersion: 5.4

packages:

  /@scope/one/1.0.0:
    resolution: {integrity: sha512-a}

  /two/2.0.0:
    resolution: {integrity: sha512-b}
"""
check("legacy v5 slash style", names(lp.pnpm(PNPM_LEGACY)), {"@scope/one", "two"})
# A legacy scoped key must not also register a bogus package literally named "/".
check("legacy keys do not leak a '/' package", "/" in lp.pnpm(PNPM_LEGACY), False)

# --------------------------------------------------------------------------
print("\nCargo.lock")
CARGO = """version = 3

[[package]]
name = "serde"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "aaa"

[[package]]
name = "velocity-rs"
version = "0.1.0"
source = "git+https://github.com/velocity-exchange/velocity-v1?branch=master#deadbeef"

[[package]]
name = "local-crate"
version = "0.1.0"

[metadata]
"checksum serde 1.0.0" = "aaa"
"""
check("cargo names", names(lp.cargo(CARGO)), {"serde", "velocity-rs", "local-crate"})
check("cargo registry source", lp.cargo(CARGO)["serde"],
      {"registry+https://github.com/rust-lang/crates.io-index"})
check("cargo git source drops the pinned revision", lp.cargo(CARGO)["velocity-rs"],
      {"git+https://github.com/velocity-exchange/velocity-v1?branch=master"})
check("cargo path dependency", lp.cargo(CARGO)["local-crate"], {"path"})
check("cargo version bump produces no finding",
      findings(CARGO, CARGO.replace('name = "serde"\nversion = "1.0.0"',
                                    'name = "serde"\nversion = "1.0.1"'), "Cargo.lock"), [])
check("cargo branch-tracking commit bump produces no finding",
      findings(CARGO, CARGO.replace("#deadbeef", "#cafebabe"), "Cargo.lock"), [])
# The resolved commit is dropped, but an explicitly declared rev is part of the source:
# repointing a git dependency at a chosen commit is a deliberate act, not a bump.
CARGO_REV = CARGO.replace("?branch=master#deadbeef", "?rev=aaaaaaa#deadbeef")
check("cargo declared rev is kept in the source",
      lp.cargo(CARGO_REV)["velocity-rs"],
      {"git+https://github.com/velocity-exchange/velocity-v1?rev=aaaaaaa"})
check("cargo repin to a different declared rev is reported",
      findings(CARGO_REV, CARGO_REV.replace("?rev=aaaaaaa", "?rev=bbbbbbb"), "Cargo.lock"),
      [("source", "velocity-rs",
        "git+https://github.com/velocity-exchange/velocity-v1?rev=bbbbbbb")])
check("cargo swapping a git remote for another host is reported",
      findings(CARGO, CARGO.replace("github.com/velocity-exchange/velocity-v1",
                                    "evil.example/velocity-v1"), "Cargo.lock"),
      [("source", "velocity-rs", "git+https://evil.example/velocity-v1?branch=master")])
check("cargo registry swap is reported",
      findings(CARGO, CARGO.replace("registry+https://github.com/rust-lang/crates.io-index",
                                    "registry+https://evil.example/index"), "Cargo.lock"),
      [("source", "serde", "registry+https://evil.example/index")])
check("cargo new crate is reported",
      findings(CARGO, CARGO + '\n[[package]]\nname = "evil"\nversion = "1.0.0"\n', "Cargo.lock"),
      [("new", "evil", "path")])

# --------------------------------------------------------------------------
print("\nuv.lock")
UV = """version = 1
revision = 2
requires-python = ">=3.10"

[[package]]
name = "accumulation-tree"
version = "0.6.4"
source = { registry = "https://pypi.org/simple" }
sdist = { url = "https://files.pythonhosted.org/packages/ac/dc/accumulation_tree-0.6.4.tar.gz", hash = "sha256:aaa", size = 12635 }

[[package]]
name = "calibration"
version = "0.1.0"
source = { virtual = "." }
dependencies = [
    { name = "numpy" },
]

[package.metadata]
requires-dist = [
    { name = "numpy", specifier = ">=1.0" },
]

[[package]]
name = "numpy"
version = "2.2.0"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "numpy"
version = "2.0.0"
source = { registry = "https://pypi.org/simple" }
"""
check("uv names, with a duplicated name counted once", names(lp.uv(UV)),
      {"accumulation-tree", "calibration", "numpy"})
check("uv registry source", lp.uv(UV)["numpy"], {"registry:https://pypi.org/simple"})
check("uv virtual root", lp.uv(UV)["calibration"], {"virtual:."})
check("uv sdist/wheel URLs are not mistaken for the source",
      lp.uv(UV)["accumulation-tree"], {"registry:https://pypi.org/simple"})
check("uv requires-dist entries are not packages", "specifier" in lp.uv(UV), False)
check("uv version bump produces no finding",
      findings(UV, UV.replace('version = "2.2.0"', 'version = "2.3.0"'), "uv.lock"), [])
check("uv index swap is reported",
      findings(UV, UV.replace('name = "numpy"\nversion = "2.2.0"\nsource = { registry = "https://pypi.org/simple" }',
                              'name = "numpy"\nversion = "2.2.0"\nsource = { registry = "https://evil.example/simple" }'),
               "uv.lock"),
      [("source", "numpy", "registry:https://evil.example/simple")])
check("uv switch to a git source is reported",
      findings(UV, UV.replace('name = "accumulation-tree"\nversion = "0.6.4"\nsource = { registry = "https://pypi.org/simple" }',
                              'name = "accumulation-tree"\nversion = "0.6.4"\nsource = { git = "https://evil.example/x?rev=a#deadbeef" }'),
               "uv.lock"),
      [("source", "accumulation-tree", "git:https://evil.example/x?rev=a")])
check("uv has its own parser, not Cargo's", lp.PARSERS["uv.lock"] is lp.uv, True)

# --------------------------------------------------------------------------
print("\nunparseable input is a hard error, never an empty result")


def exits(label, name, text):
    path = write(name, text)
    try:
        result = lp.extract(path)
    except SystemExit:
        print(f"  ok    {label}")
        return
    failures.append(f"{label}\n     got:  returned {show(result)}\n     want: SystemExit")
    print(f"  FAIL  {label}")


exits("bun.lock that is not JSON at all", "bun.lock", "this is not a lockfile\n")
exits("bun.lock whose packages value is not an object", "bun.lock",
      '{"lockfileVersion": 1, "packages": []}')
exits("bun.lock emptied while workspaces still declare dependencies", "bun.lock",
      '{"lockfileVersion": 1, "workspaces": {"": {"dependencies": {"lodash": "^4"}}},'
      ' "packages": {}}')
exits("bun.lock entry that is not an array", "bun.lock",
      '{"lockfileVersion": 1, "packages": {"a": "not-an-array"}}')
exits("yarn.lock with no entries and no header", "yarn.lock", "garbage\nmore garbage\n")
exits("berry yarn.lock with no resolutions", "yarn.lock", "__metadata:\n  version: 8\n")
exits("pnpm-lock.yaml with no lockfileVersion", "pnpm-lock.yaml", "packages:\n  nonsense\n")
exits("Cargo.lock with neither packages nor a version header", "Cargo.lock", "garbage\n")
exits("Cargo.lock block with no name", "Cargo.lock", 'version = 3\n\n[[package]]\nversion = "1.0"\n')
exits("uv.lock with neither packages nor a version header", "uv.lock", "garbage\n")

# A lockfile that legitimately records nothing is still allowed to be empty.
check("an empty but well-formed Cargo.lock is not an error",
      lp.extract(write("Cargo.lock", "version = 4\n")), {})
check("an empty but well-formed yarn.lock is not an error",
      lp.extract(write("yarn.lock", "# yarn lockfile v1\n")), {})
check("an empty but well-formed pnpm-lock.yaml is not an error",
      lp.extract(write("pnpm-lock.yaml", "lockfileVersion: '9.0'\n")), {})
check("an empty but well-formed bun.lock is not an error",
      lp.extract(write("bun.lock", '{"lockfileVersion": 1, "packages": {}}')), {})

# --------------------------------------------------------------------------
print("\nfindings stay one per line")
# A package name is attacker-controlled text that ends up in a tab-separated record.
# A newline or tab inside it would forge an extra finding, or split one in two.
NASTY = ('{"lockfileVersion": 1, "packages": {'
         '"a": ["ev\\til@1.0.0", "", {}, "h"],'
         '"b": ["ev\\nil2@1.0.0", "", {}, "h"]}}')
nasty = lp.bun(NASTY)
check("tabs and newlines are escaped out of names",
      names(nasty), {"ev\\x09il", "ev\\x0ail2"})
rows = list(lp.diff({}, nasty))
check("every finding is a single line", all("\n" not in "\t".join(r) for r in rows), True)
check("every finding has exactly three fields",
      all(len("\t".join(r).split("\t")) == 3 for r in rows), True)

# --------------------------------------------------------------------------
print("\nsign-off digest")
SET_A = ["Cargo.lock\tnew\tserde\tpath", "bun.lock\tnew\tevil\tregistry:default"]
check("the digest does not depend on ordering",
      lp.digest(SET_A), lp.digest(list(reversed(SET_A))))
check("the digest ignores blank lines and trailing newlines",
      lp.digest(SET_A), lp.digest([SET_A[0] + "\n", "", SET_A[1], "\n"]))
check("adding a finding changes the digest",
      lp.digest(SET_A) != lp.digest(SET_A + ["bun.lock\tnew\tmore\tregistry:default"]), True)
check("removing a finding changes the digest",
      lp.digest(SET_A) != lp.digest(SET_A[:1]), True)
check("the digest is hex and long enough to resist a second preimage",
      len(lp.digest(SET_A)) >= 24 and all(c in "0123456789abcdef" for c in lp.digest(SET_A)), True)

# --------------------------------------------------------------------------
print("\ndispatch and CLI")
check("an unsupported filename exits non-zero", run("package-lock.json", expect=1).returncode, 1)
check("no arguments exits non-zero", run(expect=1).returncode, 1)

missing = Path(tempfile.mkdtemp()) / "bun.lock"
check("an absent base means everything is new", lp.extract(missing), {})
check("an absent base yields 'new' findings, not 'source' ones",
      sorted(lp.diff(lp.extract(missing), lp.bun(SUB_BASE))),
      [("new", "husky", "registry:default")])

base = write("bun.lock", BUN)
head = write("bun.lock", MERGED)
added = run(base, head)
check("diff mode reports only additions", added.stdout.strip(), "new\tevil\tregistry:default")
check("single-file mode prints name and source",
      sorted(run(base).stdout.strip().splitlines())[0], "@coral-xyz/anchor\tregistry:default")
check("identical files report nothing", run(base, base).stdout.strip(), "")
check("a pure removal is not an addition", run(head, base).stdout.strip(), "")

tsv = write("findings.tsv", "\n".join(SET_A) + "\n")
check("--digest matches the library digest",
      run("--digest", tsv).stdout.strip(), lp.digest(SET_A))
tsv_reordered = write("findings.tsv", "\n".join(reversed(SET_A)) + "\n")
check("--digest is order independent on the command line too",
      run("--digest", tsv_reordered).stdout.strip(), run("--digest", tsv).stdout.strip())

# --------------------------------------------------------------------------
print()
if failures:
    print(f"{len(failures)} failure(s):")
    for f in failures:
        print(f"  - {f}")
    sys.exit(1)
print("all tests passed")
