#Name:Eric Schwab
#Student ID: 041271210

import sys
import xml.etree.ElementTree as ET
import yaml
import json


class AuditError(Exception):
    "Custom exception for audit errors."


class Device:
    "Represents a network device."

    def __init__(self, device_id, role, os_version, owner, interfaces):
        "Initialize a network device."
        self.device_id = device_id
        self.role = role
        self.os_version = os_version
        self.owner = owner
        self.interfaces = interfaces

    def count_interfaces(self):
        "Count interface statuses for this device."
        counts = {"up": 0, "down": 0, "other": 0}

        for interface in self.interfaces:
            status = interface.lower()

            if status == "up":
                counts["up"] += 1
            elif status == "down":
                counts["down"] += 1
            else:
                counts["other"] += 1

        return counts

def read_inventory(filename):
    "Read devices from an XML inventory file."
    try:
        tree = ET.parse(filename)
        root = tree.getroot()
    except (OSError, ET.ParseError) as error:
        raise AuditError(f"{filename}: {error}") from error

    site = root.get("site")
    devices = []
    skipped_devices = 0

    for element in root.findall("device"):
        device_id = element.get("id")

        if not device_id:
            skipped_devices += 1
            continue

        role = element.get("role", "")
        os_version = element.get("os", "")

        owner_element = element.find("owner")
        owner = ""

        if owner_element is not None and owner_element.text:
            owner = owner_element.text.strip()

        interfaces = []

        for interface in element.findall("interface"):
            status = interface.get("status", "")
            interfaces.append(status)

        device = Device(
            device_id,
            role,
            os_version,
            owner,
            interfaces
        )

        devices.append(device)

    return site, devices, skipped_devices

def read_policy(filename):
    "Read the compliance policy from a YAML file."
    try:
        with open(filename, "r", encoding="utf-8") as file:
            policy = yaml.safe_load(file)

    except (OSError, yaml.YAMLError) as error:
        raise AuditError(f"{filename}: {error}") from error

    if policy is None:
        policy = {}

    if not isinstance(policy, dict):
        raise AuditError(f"{filename}: policy must be a mapping")

    return policy

def compare_versions(found, required):
    "Compare numeric operating system version parts."
    found_parts = [int(part) for part in found.split(".")]
    required_parts = [int(part) for part in required.split(".")]

    length = max(len(found_parts), len(required_parts))

    found_parts.extend([0] * (length - len(found_parts)))
    required_parts.extend([0] * (length - len(required_parts)))

    return found_parts >= required_parts

def audit_devices(devices, policy):
    "Check devices against the compliance policy."
    violations = []
    compliant = []

    roles = {}
    interfaces = {"up": 0, "down": 0, "other": 0}

    for device in devices:
        device_violations = []

        roles[device.role] = roles.get(device.role, 0) + 1

        interface_counts = device.count_interfaces()

        for status in interfaces:
            interfaces[status] += interface_counts[status]

        min_os = policy.get("min_os", {})

        if "min_os" in policy:
            if device.role not in min_os:
                device_violations.append({
                    "device": device.device_id,
                    "type": "unknown_role",
                    "role": device.role
                })
            elif not compare_versions(
                device.os_version,
                min_os[device.role]
            ):
                device_violations.append({
                    "device": device.device_id,
                    "type": "os_outdated",
                    "found": device.os_version,
                    "required": min_os[device.role]
                })

        if policy.get("require_owner", False) and not device.owner:
            device_violations.append({
                "device": device.device_id,
                "type": "missing_owner"
            })

        if "max_down_interfaces" in policy:
            if interface_counts["down"] > policy["max_down_interfaces"]:
                device_violations.append({
                    "device": device.device_id,
                    "type": "too_many_down",
                    "down": interface_counts["down"]
                })

        violations.extend(device_violations)

        if not device_violations:
            compliant.append(device.device_id)

    compliant.sort()

    return violations, compliant, roles, interfaces


def main():
    "Run the fleet compliance auditor."
    if len(sys.argv) != 3:
        print("usage: python pa2.py DEVICES.xml POLICY.yaml")
        sys.exit(2)

    inventory_file = sys.argv[1]
    policy_file = sys.argv[2]

    try:
        site, devices, skipped_devices = read_inventory(inventory_file)
        policy = read_policy(policy_file)

        violations, compliant, roles, interfaces = audit_devices(
            devices, policy
        )

        report = {
            "site": site,
            "total_devices": len(devices),
            "skipped_devices": skipped_devices,
            "roles": roles,
            "interfaces": interfaces,
            "violations": violations,
            "compliant": compliant
        }

        with open("audit.json", "w", encoding="utf-8") as file:
            json.dump(report, file, indent=4)

        print("Fleet Compliance Audit Complete")
        print("Total devices:", len(devices))
        print("Skipped devices:", skipped_devices)
        print("Violations:", len(violations))
        print("Compliant devices:", len(compliant))
        print("Report saved to audit.json")

    except AuditError as error:
        print(f"Error: {error}")
        sys.exit(1)

if __name__ == "__main__":
    main()


