#!/usr/bin/env python3
"""Checks that the specification version is stated consistently and moves with the text.

spec/VERSION is the one source. README.md and chapter 00 must state the same version, and
CHANGELOG.md must have an entry for it. Compared with the newest v<core-release>-<revision> tag
before HEAD, spec/VERSION must not be older, must be the next version if spec/ has changed since that tag, and
must equal any version tag on HEAD (as committed there).

Needs the repository's tags: in GitHub Actions, check out with fetch-depth: 0.
"""

import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
VERSION_FORMAT = re.compile(r"v(\d+(?:\.\d+)*)-(\d+)")
STATED = {
    "README.md": r"Specification version `([^`]*)`",
    "spec/00-introduction.md": r"\| Specification version \| `([^`]*)` \|",
}


def parse(version):
    """`v32.1-3` becomes `((32, 1), 3)`, which orders versions correctly; None if malformed."""
    match = VERSION_FORMAT.fullmatch(version)
    if match is None:
        return None
    return tuple(int(part) for part in match.group(1).split(".")), int(match.group(2))


def git(*args):
    return subprocess.run(["git", "-C", str(ROOT), *args], capture_output=True, text=True, check=True).stdout


def spec_changed_since(tag):
    # spec/VERSION is left out so that a tag cut before the file existed compares cleanly.
    result = subprocess.run(
        ["git", "-C", str(ROOT), "diff", "--quiet", tag, "--", "spec", ":(exclude)spec/VERSION"]
    )
    if result.returncode not in (0, 1):
        sys.exit(f"git diff against {tag} failed")
    return result.returncode == 1


def check():
    version = (ROOT / "spec" / "VERSION").read_text().strip()
    parsed = parse(version)
    if parsed is None:
        return [f"spec/VERSION holds {version!r}, not a version of the form v<core-release>-<revision>"]

    errors = []
    for path, pattern in STATED.items():
        stated = re.findall(pattern, (ROOT / path).read_text())
        if stated != [version]:
            errors.append(f"{path} states specification version {stated or 'nothing'}, spec/VERSION holds {version}")
    entries = re.findall(r"^## (\S+)", (ROOT / "CHANGELOG.md").read_text(), re.MULTILINE)
    if version not in entries:
        errors.append(f"CHANGELOG.md has no '## {version}' entry")

    # A tag on HEAD is the release being checked, so it must follow the newest tag before HEAD.
    tags = [tag for tag in git("tag", "--no-contains", "HEAD", "--list", "v*").split() if parse(tag)]
    if not tags:
        return errors + ["no version tags found; fetch them (in GitHub Actions, fetch-depth: 0)"]
    latest = max(tags, key=parse)
    latest_parsed = parse(latest)
    (latest_core, latest_revision), (core, revision) = latest_parsed, parsed
    next_version = f"v{'.'.join(map(str, latest_core))}-{latest_revision + 1}"
    if parsed < latest_parsed:
        errors.append(f"spec/VERSION holds {version}, older than the newest tag {latest}")
    elif parsed == latest_parsed:
        if spec_changed_since(latest):
            errors.append(
                f"spec/ has changed since {latest}, so spec/VERSION must name the next revision, "
                f"{next_version}, with an entry in CHANGELOG.md"
            )
    elif not (core == latest_core and revision == latest_revision + 1 or core > latest_core and revision == 1):
        errors.append(
            f"spec/VERSION holds {version}, which skips versions after {latest}; "
            f"expected {next_version} or revision 1 of a newer Bitcoin Core release"
        )

    # Read from HEAD, not the working tree, so that editing right after a tag is not an error.
    head_tags = [tag for tag in git("tag", "--points-at", "HEAD", "--list", "v*").split() if parse(tag)]
    if head_tags:
        committed = subprocess.run(
            ["git", "-C", str(ROOT), "show", "HEAD:spec/VERSION"], capture_output=True, text=True
        )
        committed = committed.stdout.strip() if committed.returncode == 0 else "nothing"
        for tag in head_tags:
            if tag != committed:
                errors.append(f"HEAD is tagged {tag} but its spec/VERSION holds {committed}")
    return errors


def main():
    errors = check()
    for error in errors:
        print(error, file=sys.stderr)
    if errors:
        sys.exit(1)
    print(f"specification version {(ROOT / 'spec' / 'VERSION').read_text().strip()}: consistent")


if __name__ == "__main__":
    main()
