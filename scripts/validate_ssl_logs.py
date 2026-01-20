#!/usr/bin/env python3
"""Validate logs from ssl_client2 and ssl_server2.

On success, print nothing and return 0.
On a validation failure, print a short error message and return 1.
On a command line or parse error, die with an exception and return 1.
"""

# Copyright The Mbed TLS Contributors
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

import argparse
import sys
from typing import Callable, Dict, List, Optional

from mbedtls_framework import ssl_log_parser



def match_random(client_log: ssl_log_parser.Info,
                 server_log: ssl_log_parser.Info) -> Optional[str]:
    """Check that both sides have the same idea of client_random and server_random."""
    client_client_randoms = client_log.dumps['client hello, random bytes']
    client_server_randoms = client_log.dumps['server hello, random bytes']
    server_client_randoms = server_log.dumps['client hello, random bytes']
    server_server_randoms = server_log.dumps['server hello, random bytes']
    if len(client_client_randoms) != len(server_client_randoms):
        return ('Client and server disagree on the number of client_random ' +
                f'({len(client_client_randoms)} != {len(server_client_randoms)})')
    if len(client_server_randoms) != len(server_server_randoms):
        return ('Client and server disagree on the number of server_random ' +
                f'({len(client_server_randoms)} != {len(server_server_randoms)})')
    for n, (c, s) in enumerate(zip(client_client_randoms, server_client_randoms)):
        if c != s:
            return f'Client and server disagree on client random #{n}'
    for n, (c, s) in enumerate(zip(client_server_randoms, server_server_randoms)):
        if c != s:
            return f'Client and server disagree on server random #{n}'
    return None


Task = Callable[[ssl_log_parser.Info, ssl_log_parser.Info], Optional[str]]

TASKS = {
    'match_random': match_random,
} #type: Dict[str, Task]

def validate(client_log: ssl_log_parser.Info,
             server_log: ssl_log_parser.Info,
             tasks: List[str]) -> Optional[str]:
    """Perform validation tasks on a pair of matching logs.

    Return None if the validation succeeds, a human-oriented error message
    otherwise.
    """
    for task_name in tasks:
        task = TASKS[task_name]
        outcome = task(client_log, server_log)
        if outcome is not None:
            return outcome
    return None


def main() -> int:
    """Command line entry point."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--list-tasks',
                        help='List available tasks and exit')
    parser.add_argument('client_log', metavar='FILE',
                        help='Client log file ($CLI_OUT or ?-cli-*.log)')
    parser.add_argument('server_log', metavar='FILE',
                        help='Server log file ($SRV_OUT or ?-srv-*.log)')
    parser.add_argument('tasks', metavar='TASK',
                        nargs='+', #action='append',
                        help='Tasks to perform (use --list-tasks to see supported task names)')
    args = parser.parse_args()
    if args.list_tasks:
        for task_name in sorted(TASKS.keys()):
            print(task_name)
        return 0
    client_log = ssl_log_parser.parse_log_file(args.client_log)
    server_log = ssl_log_parser.parse_log_file(args.server_log)
    outcome = validate(client_log, server_log, args.tasks)
    if outcome is None:
        return 0
    else:
        if outcome and outcome[-1] != '\n':
            outcome += '\n'
        sys.stderr.write(outcome)
        return 1

if __name__ == '__main__':
    sys.exit(main())
