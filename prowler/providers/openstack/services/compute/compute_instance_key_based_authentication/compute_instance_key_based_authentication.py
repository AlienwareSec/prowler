from typing import List

from prowler.lib.check.models import Check, CheckReportOpenStack
from prowler.providers.openstack.services.compute.compute_client import compute_client


class compute_instance_key_based_authentication(Check):
    """Ensure compute instances use SSH key-based authentication instead of passwords."""

    def execute(self) -> List[CheckReportOpenStack]:
        findings: List[CheckReportOpenStack] = []

        for instance in compute_client.instances:
            report = CheckReportOpenStack(metadata=self.metadata(), resource=instance)
            report.resource_id = instance.id
            report.resource_name = instance.name
            report.region = instance.region

            if instance.key_name:
                report.status = "PASS"
                report.status_extended = (
                    f"Instance {instance.name} ({instance.id}) is configured with "
                    f"SSH key-based authentication (keypair: {instance.key_name})."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"Instance {instance.name} ({instance.id}) does not have SSH "
                    f"key-based authentication configured (no keypair assigned)."
                )

            findings.append(report)

        return findings
