Eric Schwab
041271210

import sys
import xml.etree.ElementTree as ET
import yaml
import json


class AuditError(Exception):
    """Custom exception for audit input errors."""


class Device:
    """Represents a network device."""

    def __init__(self, device_id, role, os_version, owner, interfaces):
        self.device_id = device_id
        self.role = role
        self.os_version = os_version
        self.owner = owner
        self.interfaces = interfaces


def main():
    """Runs the fleet compliance audit."""
    print("Fleet Compliance Auditor - starting...")


if __name__ == "__main__":
    main()

    