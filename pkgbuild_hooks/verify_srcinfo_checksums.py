"""Verify .SRCINFO checksums for local files."""
import argparse
import hashlib
import mmap
import sys
from typing import Any, Dict, Iterable, Optional, Sequence

from srcinfo.parse import parse_srcinfo

# (pkgbuild_name, hashlib_name)
HASHES = [
    ("md5",) * 2,
    ("sha1",) * 2,
    ("sha224",) * 2,
    ("sha256",) * 2,
    ("sha384",) * 2,
    ("sha512",) * 2,
    ("b2", "blake2b"),
]


def format_strinfo_error(error: Any, filename: Optional[str] = None) -> str:
    """Format a strinfo error as a string."""
    # srcinfo is on major version 0 and the error format is ad-hoc and undocumented so
    # this is flexible in case the format changes.
    # Current format: {'line': Int, 'error': [Str]}
    # with only a single error message in the error list.
    filename_prefix = "" if filename is None else f"{filename}:"

    try:
        line = error["line"]
        messages = error["error"]
    except KeyError:
        return filename_prefix + str(error)

    if isinstance(messages, str):
        message = messages
    else:
        try:
            message = "; ".join(messages)
        except TypeError:
            message = str(messages)

    return f"{filename_prefix}{line}: {message}"


def verify_checksums(sources: Iterable[str], hashes: Dict[str, Sequence[str]]) -> bool:
    """Verify checksums for local files.

    Prints a message whenever there is a mismatch.

    Args:
        sources: An iterable of source strings.
        hashes: A dictionary of hash name -> hashes.
            For each entry, the list of hashes corresponds to `sources`
            in order but may be shorter.

    Returns:
        True if no checksums are mismatched, otherwise False.
    """
    valid = True
    hashlib_warnings = set()
    for i, source in enumerate(sources):
        try:
            source_file, _ = source.split("::")
        except ValueError:
            source_file = source

        for hashname, source_hashes in hashes.items():
            try:
                expected_digest = source_hashes[i]
            except IndexError:
                continue

            if expected_digest.lower() == "skip":
                continue

            try:
                h = hashlib.new(hashname)
            except ValueError:
                # Hopefully unlikely. As of the time of writing, all of HASHES are
                # in hashes.algorithms_guaranteed.
                if hashname not in hashlib_warnings:
                    print(
                        f"Warning: Your version of hashlib doesn't support {hashname}"
                    )
                    hashlib_warnings.add(hashname)
                continue

            try:
                with open(source_file, "rb") as f:
                    # Memory map in case the file is large
                    contents = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
                    h.update(contents)  # type: ignore
            except FileNotFoundError:
                break  # No point trying other hashes

            actual_digest = h.hexdigest()

            if expected_digest != actual_digest:
                print(source_file)
                print(f"\tExpected ({hashname}): {expected_digest}")
                print(f"\tActual   ({hashname}): {actual_digest}")
                valid = False
    return valid


def verify_srcinfo_checksums(filename: str) -> bool:
    """Verify the checksums of local files listed in the given SRCINFO file.

    Prints messages describing each mismatch.

    Args:
        filename: Path to a SRCINFO data file.

    Returns:
        True if no checksums are mismatched, otherwise False.
    """
    with open(filename, "r") as f:
        srcinfo_data = f.read()

    info, errors = parse_srcinfo(srcinfo_data)
    if errors:
        message = "\n".join(format_strinfo_error(error, filename) for error in errors)
        raise ValueError(message)

    valid = True
    for arch in [None] + info.get("arch", []):
        suffix = "" if arch is None else f"_{arch}"
        try:
            sources = info[f"source{suffix}"]
        except KeyError:
            continue
        hashes = {}
        for pkgbuild_hash, hashlib_hash in HASHES:
            try:
                hashes[hashlib_hash] = info[f"{pkgbuild_hash}sums{suffix}"]
            except KeyError:
                pass
        valid &= verify_checksums(sources, hashes)
    return valid


def parse_args(argv=None):
    """Parse command-line arguments.

    Args:
        args: A list of argument strings to use instead of sys.argv.

    Returns:
        An `argparse.Namespace` object containing the parsed arguments.
    """
    parser = argparse.ArgumentParser(
        description=__doc__.splitlines()[0] if __doc__ else None,
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "files",
        type=str,
        nargs="*",
        default=(".SRCINFO",),
        metavar="FILE",
        help="SRCINFO data file(s) to read",
    )
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(argv)
    valid = True
    for filename in args.files:
        try:
            valid &= verify_srcinfo_checksums(filename)
        except Exception as e:
            print(e)
            return 1
    return 0 if valid else 1


if __name__ == "__main__":
    sys.exit(main())
