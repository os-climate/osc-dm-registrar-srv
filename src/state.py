# Copyright 2024 Broda Group Software Inc.
#
# Use of this source code is governed by an MIT-style
# license that can be found in the LICENSE file or at
# https://opensource.org/licenses/MIT.
#
# Created:  2024-04-15 by eric.broda@brodagroupsoftware.com


"""
Dictionary containing global state
"""
global_state = {}

def gstate(name: str, value: any=None):
    """
    Global state manager for registration state

    If registration is provided then global state is set to True
    and instance is returned.

    If registration does not exist then False will be returned.
    Returns registration state in global state if it exists.

    Args:
        registration (any, optional, default: True): registration state to store

    Returns:
        any: database instance in global state.
    """

    global global_state
    if value is not None:
        global_state[name] = value
        return value

    value = None
    if name in global_state:
        value = global_state[name]
    return value
