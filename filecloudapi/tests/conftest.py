# Copyright (c) 2024 FileCloud. All Rights Reserved.
"""Unit tests configuration file."""

import log


def pytest_configure(config):
    """Disable verbose output when running tests."""
    log.init(debug=True)

    terminal = config.pluginmanager.getplugin("terminal")
    terminal.TerminalReporter.showfspath = False
