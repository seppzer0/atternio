import os
import shutil
from typing import List
from pathlib import Path


def ucopy(src: os.PathLike, dst: os.PathLike, exceptions: List[str] = []) -> None:
    """A universal method to copy files into desired destinations.

    :param path src: Source path.
    :param path dst: Destination path.
    :param List[str] exceptions: Elements that will not be removed.
    """
    # for a directory (it's contents)
    if src.is_dir():
        if not dst.is_dir():
            os.mkdir(dst)
        contents = os.listdir(src)
        for e in contents:
            # do not copy restricted files
            if e not in exceptions and e != src:
                src_e = Path(src, e)
                dst_e = Path(dst, e)
                if src_e.is_dir():
                    shutil.copytree(src_e, dst_e)
                elif src_e.is_file():
                    shutil.copy(src_e, dst_e)
    # for a single file
    elif src.is_file():
        shutil.copy(src, dst)
