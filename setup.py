"""Legacy setup shim.

All project metadata lives in ``pyproject.toml``. This file remains only so
that ``python setup.py <command>`` invocations continue to work for tools that
have not yet switched to the PEP 517 build interface.
"""

from setuptools import setup

setup()
