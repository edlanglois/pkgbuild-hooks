"""Check .SRCINFO against makepkg and update if necessary."""
import subprocess
import sys


def main(args=None):
    try:
        result = subprocess.run(["makepkg", "--printsrcinfo"], capture_output=True)
    except FileNotFoundError as e:
        print(str(e))
        return 1
    if result.returncode != 0:
        print(result.stderr.decode(), end="")
        return 1

    srcinfo_filename = ".SRCINFO"
    try:
        with open(srcinfo_filename, "rb") as f:
            srcinfo_contents = f.read()
    except FileNotFoundError:
        srcinfo_contents = None

    if srcinfo_contents != result.stdout:
        print(
            "Missing" if srcinfo_contents is None else "Mismatched",
            ".SRCINFO. Updating",
        )
        with open(srcinfo_filename, "wb") as f:
            f.write(result.stdout)
        return 1


if __name__ == "__main__":
    sys.exit(main())
