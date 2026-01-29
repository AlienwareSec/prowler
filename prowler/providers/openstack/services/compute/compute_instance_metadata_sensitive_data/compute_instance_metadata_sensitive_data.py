import re
from typing import List

from prowler.lib.check.models import Check, CheckReportOpenStack
from prowler.providers.openstack.services.compute.compute_client import compute_client


class compute_instance_metadata_sensitive_data(Check):
    """Ensure compute instance metadata does not contain sensitive data like passwords or API keys."""

    def execute(self) -> List[CheckReportOpenStack]:
        findings: List[CheckReportOpenStack] = []

        # Regex patterns for detecting sensitive data
        sensitive_patterns = {
            "password": re.compile(
                r"(password|passwd|pwd|pass)(\s*[:=]|$|_)", re.IGNORECASE
            ),
            "api_key": re.compile(
                r"(api[-_]?key|apikey|access[-_]?key)", re.IGNORECASE
            ),
            "secret": re.compile(r"(secret|token|auth)(\s*[:=]|$|_)", re.IGNORECASE),
            "private_key": re.compile(r"BEGIN\s+(RSA\s+)?PRIVATE\s+KEY", re.IGNORECASE),
            "connection_string": re.compile(
                r"(jdbc|mongodb|mysql|postgresql|redis)://", re.IGNORECASE
            ),
        }

        for instance in compute_client.instances:
            report = CheckReportOpenStack(metadata=self.metadata(), resource=instance)
            report.resource_id = instance.id
            report.resource_name = instance.name
            report.region = instance.region

            # Check metadata for sensitive patterns
            detected_patterns = []
            for key, value in instance.metadata.items():
                # Check both key and value
                for pattern_name, pattern in sensitive_patterns.items():
                    if pattern.search(key) or pattern.search(str(value)):
                        detected_patterns.append(f"{pattern_name} in '{key}'")
                        break  # Only report one match per key

            if not detected_patterns:
                report.status = "PASS"
                if instance.metadata:
                    report.status_extended = (
                        f"Instance {instance.name} ({instance.id}) metadata does not "
                        f"contain sensitive data patterns."
                    )
                else:
                    report.status_extended = (
                        f"Instance {instance.name} ({instance.id}) has no metadata "
                        f"(no sensitive data exposure risk)."
                    )
            else:
                report.status = "FAIL"
                pattern_list = ", ".join(set(detected_patterns))
                report.status_extended = (
                    f"Instance {instance.name} ({instance.id}) metadata contains "
                    f"potential sensitive data: {pattern_list}."
                )

            findings.append(report)

        return findings
