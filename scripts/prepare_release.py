#!/usr/bin/env python3
"""Prepare to release TF-PSA-Crypto or Mbed TLS.

This script constructs a release candidate branch and release artifacts.
It must run from a clean git worktree with initialized, clean git submodules.
When making an Mbed TLS >=4 release, the tf-psa-crypto submodule should
already contain a TF-PSA-Crypto release candidate.
"""

# Copyright The Mbed TLS Contributors
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

################################################################

#### Tips for maintainers ####

# This script insists on having a clean git checkout, including
# submodules. If you want to modify it, either make your changes in
# a separate worktree, or commit your changes first and update
# submodules in the parent repositories.

#### Architectural notes ####

# The process of preparing a release consists of some information
# gathering about the branch to release in the `Info` class, then
# a series of steps in `XxxStep` classes.

# Information gathering is performed by the `Info` constructor.
# Any failure causes the script to abort.

# The steps run sequentially in the order defined by `ALL_STEPS`.
# Each step starts by checking precondition in `step.assert_preconditions()`,
# then does its job in `step.run()`. `assert_preconditions` should
# not change any state. `run` is expected to change state and is
# not expected to clean up if an error occurs.

# This script is expected to perform a release reliably, so it
# should try to detect dodgy conditions and abort. It should avoid
# silently outputting garbage. Nonetheless, human review of the
# result is still expected.

################################################################


import argparse
import os
import pathlib
import re
import subprocess
import sys
import typing
from typing import Dict, List, Optional, Sequence


PathOrString = typing.Union[os.PathLike, str]


class InformationGatheringError(Exception):
    """Problem detected while gathering information."""
    pass


class Options(typing.NamedTuple):
    """Options controlling the behavior of the release process.

    Each field here should have an associated command line option
    declared in main().
    """
    # Directory where the release artifacts will be placed.
    artifact_directory: pathlib.Path
    # Version to release (None to read it from ChangeLog).
    version: Optional[str]

DEFAULT_OPTIONS = Options(
    artifact_directory=pathlib.Path(os.pardir),
    version=None)


class Info:
    """Information about the intended release.

    This class contains information gathered from the product tree as well
    as from the command line.
    """

    def _read_product_info(self) -> None:
        """Read information from the source files."""
        with open(self.top_dir / 'ChangeLog', encoding='utf-8') as changelog:
            # We deliberately read only a short portion at the top of the
            # changelog file. This reduces the risk that we'll match an
            # older release if the content near the top of the file doesn't
            # have the expected format.
            head = changelog.read(1000)
            m = re.search(r'^= *(.*?) +([0-9][-.0-9A-Za-z]+) +branch released (\S+)\n',
                          head, re.M)
            if not m:
                raise InformationGatheringError(
                    'Could not find version header line near the top of ChangeLog')
            self._product_human_name = m.group(1)
            self.old_version = m.group(2)
            self.old_release_date = m.group(3)

    @staticmethod
    def _product_machine_name_from_human_name(_human_name: str) -> str:
        """Determine the name used in release tags and file names."""
        if _human_name == 'TF-PSA-Crypto':
            return 'tf-psa-crypto'
        elif _human_name == 'Mbed TLS':
            return 'mbedtls'
        else:
            raise InformationGatheringError(
                f'Could not determine product (found "{_human_name}" in ChangeLog)')

    def __init__(self, top_dir: str, options: Options) -> None:
        """Parse the source files to obtain information about the product.

        Look for the product under `top_dir`.

        Optional parameters can override the supplied information:
        * `version`: version to release.
        """
        self.top_dir = pathlib.Path(top_dir)
        self._read_product_info()
        if options.version is None:
            self._release_version = self.old_version
        else:
            self._release_version = options.version
        self._product_machine_name = \
            self._product_machine_name_from_human_name(self._product_human_name)

    @property
    def product_human_name(self) -> str:
        """Human-readable product name, e.g. 'Mbed TLS'."""
        return self._product_human_name

    @property
    def product_machine_name(self) -> str:
        """Machine-frieldly product name, e.g. 'mbedtls'."""
        return self._product_machine_name

    @property
    def version(self) -> str:
        """Version string for the relase."""
        return self._release_version


class Step:
    """A step on the release process.

    This is an abstract class containing some common tooling.
    Subclasses must provide the following methods:
    * `name()` returning a unique name for each step.
    * `run()` doing the work. Raise an exception if something goes wrong.

    Subclasses may override the following methods:
    * `assert_preconditions()` is called to perform sanity checks before
      calling `run()`.
    """

    @classmethod
    def name(cls) -> str:
        """The name of this step."""
        raise NotImplementedError

    def __init__(self, options: Options, info: Info) -> None:
        """Instantiate the release step for the given product directory.

        This constructor may analyze the contents of the product tree,
        but it does not require other steps to have run.
        """
        self.options = options
        self.info = info
        self._submodules = None #type: Optional[List[str]]

    @staticmethod
    def _git_command(subcommand: List[str],
                     where: Optional[PathOrString] = None) -> List[str]:
        cmd = ['git']
        if where is not None:
            cmd += ['-C', str(where)]
        return cmd + subcommand

    def call_git(self, cmd: List[str],
                 where: Optional[PathOrString] = None,
                 env: Optional[Dict[str, str]] = None) -> None:
        """Run git in the source tree.

        Pass `where` to specify a submodule.
        """
        subprocess.check_call(self._git_command(cmd, where),
                              cwd=self.info.top_dir,
                              env=env)

    def read_git(self, cmd: List[str],
                 where: Optional[PathOrString] = None,
                 env: Optional[Dict[str, str]] = None) -> bytes:
        """Run git in the source tree and return the output.

        Pass `where` to specify a submodule.
        """
        return subprocess.check_output(self._git_command(cmd, where),
                                       cwd=self.info.top_dir,
                                       env=env)

    @property
    def submodules(self) -> Sequence[str]:
        """List the git submodules (recursive, but not including the top level)."""
        if self._submodules is None:
            raw = self.read_git(['submodule', '--quiet',
                                 'foreach', '--recursive',
                                 'printf %s\\\\0 "$displaypath"'])
            self._submodules = raw.decode('ascii').rstrip('\0').split('\0')
        return self._submodules

    def assert_git_status(self) -> None:
        """Abort if the working directory is not clean (no git changes).

        This includes git submodules.
        """
        self.call_git(['diff', '--quiet'])


    def assert_preconditions(self) -> None:
        """Check whether the preconditions for this step have been achieved.

        If not, raise an exception.
        """
        self.assert_git_status()

    def run(self) -> None:
        """Perform the release preparation step.

        This may create commits in the source tree or its submodules.
        """
        raise NotImplementedError


ALL_STEPS = [
] #type: Sequence[typing.Type[Step]]


def run(options: Options,
        top_dir: str,
        from_: Optional[str] = None,
        to: Optional[str] = None) -> None:
    """Run the release process (or a segment thereof)."""
    info = Info(top_dir, options)
    from_reached = (from_ is None)
    for step_class in ALL_STEPS:
        step = step_class(options, info)
        if not from_reached:
            if step.name() != from_:
                continue
            from_reached = True
        step.assert_preconditions()
        step.run()
        if step.name() == to:
            break

def main() -> None:
    """Command line entry point."""
    parser = argparse.ArgumentParser(description=__doc__)
    # Options that affect information gathering, or that affect the
    # behavior of one or more steps, should have an associated field
    # in the Options class.
    parser.add_argument('--directory',
                        default=os.curdir,
                        help='Product toplevel directory')
    parser.add_argument('--artifact-directory', '-a',
                        help='Directory where release artifacts will be placed')
    parser.add_argument('--from', metavar='STEP',
                        dest='from_',
                        help='First step to run (default: run all steps)')
    parser.add_argument('--list-steps',
                        action='store_true',
                        help='List release steps and exit')
    parser.add_argument('--to', metavar='STEP',
                        help='Last step to run (default: run all steps)')
    parser.add_argument('version', nargs='?',
                        help='The version to release (default: from ChangeLog)')
    parser.set_defaults(**DEFAULT_OPTIONS._asdict())
    args = parser.parse_args()
    if args.list_steps:
        for step in ALL_STEPS:
            sys.stdout.write(step.name() + '\n')
        return
    options = Options(
        artifact_directory=pathlib.Path(args.artifact_directory).absolute(),
        version=args.version)
    run(options, args.directory,
        from_=args.from_, to=args.to)

if __name__ == '__main__':
    main()
