import errno
import sys
import os

import hashlib
from pwnlib.util.packing import _encode

CACHE_DIR_BASE_NAME = ".asmexec-cache"


# These functions are modified versions of those found in pwntools
def get_filename_for_cache(
    command_to_run: list[str],
    asm_string: str,
    arch: str,
    includes: str,
    vma: int | None = None,
    syntax: str | None = None,
) -> str:
    cache_dir = get_cache_dir()

    hash_params = f"{arch}_{vma}_{includes}_{syntax}"
    fingerprint_params: bytes | bytearray = (
        _encode(asm_string) + _encode(hash_params) + _encode(" ".join(command_to_run))
    )
    asm_hash: str = hashlib.sha1(fingerprint_params).hexdigest()

    cache_file = os.path.join(cache_dir, asm_hash)

    return cache_file


def find_cached_version(
    command_to_run: list[str],
    asm_string: str,
    arch: str,
    includes: str,
    vma: int | None = None,
    syntax: str | None = None,
) -> tuple[str, bool]:
    cache_file = get_filename_for_cache(
        command_to_run, asm_string, arch, includes, vma, syntax
    )

    if os.path.exists(cache_file):
        print(f"Using cached assembly output from {cache_file}")

        return cache_file, True

    return cache_file, False


def get_cache_dir() -> str | None:
    """
    Directory used for caching data.
    """
    major, minor = sys.version_info[:2]

    # Attempt to create a Python version specific cache dir and its parents
    cache_dirname = f"{CACHE_DIR_BASE_NAME}-{major}.{minor}"
    cache_dirpath = os.path.join(cache_dir_base(), cache_dirname)
    try:
        os.makedirs(cache_dirpath)
    except OSError as exc:
        # If we failed for any reason other than the cache directory
        # already existing then we return none
        if exc.errno != errno.EEXIST:
            return None

    # By this time we have a cache directory which exists but we don't know
    # if it is actually writable. Some wargames e.g. pwnable.kr have
    # created dummy directories which cannot be modified by the user
    # account (owned by root).
    if os.access(cache_dirpath, os.W_OK):
        return cache_dirpath
    else:
        return None


def cache_dir_base() -> str:
    return os.environ.get(
        "XDG_CACHE_HOME", os.path.join(os.path.expanduser("~"), ".cache")
    )
