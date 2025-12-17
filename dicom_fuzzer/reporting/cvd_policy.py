"""Coordinated Vulnerability Disclosure (CVD) Policy Generator.

Generates CVD policy templates compliant with FDA June 2025 Cybersecurity Guidance.

FDA Requirements:
- Must have a documented CVD policy
- Include process for receiving vulnerability reports
- Define timelines for acknowledgment and remediation
- Establish communication channels

References:
- FDA Cybersecurity Guidance (June 2025) Section V.B
- ISO/IEC 29147:2018 (Vulnerability Disclosure)
- ISO/IEC 30111:2019 (Vulnerability Handling Processes)
- CERT Guide to Coordinated Vulnerability Disclosure

"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


@dataclass
class CVDPolicyConfig:
    """Configuration for CVD policy generation."""

    # Organization info
    organization_name: str = ""
    organization_website: str = ""
    product_name: str = ""

    # Contact information
    security_email: str = "security@example.com"
    security_pgp_key: str = ""
    security_portal_url: str = ""

    # Timeline configuration (in days)
    acknowledgment_deadline: int = 5
    initial_assessment_deadline: int = 14
    remediation_target: int = 90
    public_disclosure_deadline: int = 90

    # Scope
    in_scope_products: list[str] = field(default_factory=list)
    out_of_scope: list[str] = field(default_factory=list)

    # Recognition
    hall_of_fame: bool = True
    bug_bounty: bool = False
    bug_bounty_url: str = ""

    # Legal
    safe_harbor: bool = True
    legal_contact: str = ""


class CVDPolicyGenerator:
    """Generate Coordinated Vulnerability Disclosure policy documents."""

    def __init__(self, config: CVDPolicyConfig | None = None) -> None:
        self.config = config or CVDPolicyConfig()

    def generate_policy_markdown(self) -> str:
        """Generate CVD policy in Markdown format."""
        cfg = self.config
        now = datetime.now(UTC).strftime("%Y-%m-%d")

        policy = f"""# Coordinated Vulnerability Disclosure Policy

**Organization:** {cfg.organization_name or "[Organization Name]"}
**Product:** {cfg.product_name or "[Product Name]"}
**Effective Date:** {now}
**Version:** 1.0

---

## 1. Introduction

{cfg.organization_name or "[Organization Name]"} is committed to the security of our
products and the protection of our customers. We welcome and appreciate the responsible
disclosure of security vulnerabilities from security researchers, customers, and
industry partners.

This policy outlines our process for receiving, assessing, and responding to
vulnerability reports in accordance with ISO/IEC 29147 and FDA cybersecurity guidance.

---

## 2. Scope

### 2.1 In Scope

The following products and services are covered by this policy:

"""
        if cfg.in_scope_products:
            for product in cfg.in_scope_products:
                policy += f"- {product}\n"
        else:
            policy += f"""- {cfg.product_name or "[Product Name]"}
- Associated mobile applications
- Web portals and APIs
- Network services and protocols
"""

        policy += """
### 2.2 Out of Scope

The following are NOT covered by this policy:

"""
        if cfg.out_of_scope:
            for item in cfg.out_of_scope:
                policy += f"- {item}\n"
        else:
            policy += """- Third-party software and libraries (report to respective vendors)
- Physical security assessments
- Social engineering attacks
- Denial of Service (DoS) testing against production systems
- Vulnerabilities requiring physical access to devices
"""

        policy += f"""
---

## 3. How to Report a Vulnerability

### 3.1 Contact Information

**Security Email:** [{cfg.security_email}](mailto:{cfg.security_email})
"""

        if cfg.security_pgp_key:
            policy += f"""
**PGP Key:** {cfg.security_pgp_key}
(We encourage encryption for sensitive reports)
"""

        if cfg.security_portal_url:
            policy += f"""
**Security Portal:** [{cfg.security_portal_url}]({cfg.security_portal_url})
"""

        policy += f"""
### 3.2 Required Information

Please include the following in your report:

1. **Description:** Clear description of the vulnerability
2. **Impact:** Potential security impact and affected components
3. **Reproduction Steps:** Step-by-step instructions to reproduce
4. **Proof of Concept:** Code, screenshots, or files demonstrating the issue
5. **Environment:** Software versions, OS, configuration details
6. **Discovery Date:** When you discovered the vulnerability
7. **Contact Information:** How we can reach you for follow-up

### 3.3 Preferred Format

We accept reports in the following formats:
- Plain text or Markdown
- PDF documents
- Test files (DICOM samples, scripts, etc.)

---

## 4. Response Timeline

We commit to the following response timeline:

| Stage | Timeline | Description |
|-------|----------|-------------|
| **Acknowledgment** | {cfg.acknowledgment_deadline} business days | Confirm receipt of report |
| **Initial Assessment** | {cfg.initial_assessment_deadline} business days | Provide initial severity assessment |
| **Remediation Target** | {cfg.remediation_target} days | Target for fix development |
| **Public Disclosure** | {cfg.public_disclosure_deadline} days | Coordinated public disclosure |

*Note: Complex vulnerabilities may require extended timelines. We will communicate any
delays and work with reporters to establish mutually agreeable schedules.*

---

## 5. What to Expect

### 5.1 Our Commitment

Upon receiving your report, we will:

1. **Acknowledge** your submission within {cfg.acknowledgment_deadline} business days
2. **Assign** a tracking ID for your report
3. **Assess** the vulnerability severity using CVSS 4.0
4. **Communicate** regularly on remediation progress
5. **Coordinate** disclosure timing with you
6. **Credit** you in security advisories (if desired)

### 5.2 Severity Assessment

We use the Common Vulnerability Scoring System (CVSS) version 4.0 for severity
assessment:

| CVSS Score | Severity | Typical Response |
|------------|----------|------------------|
| 9.0 - 10.0 | Critical | Emergency patch |
| 7.0 - 8.9 | High | Priority fix |
| 4.0 - 6.9 | Medium | Standard release cycle |
| 0.1 - 3.9 | Low | Future release |

---

## 6. Responsible Disclosure Guidelines

### 6.1 Researcher Expectations

We ask that security researchers:

1. **Report promptly** - Notify us as soon as practical after discovery
2. **Avoid harm** - Do not access, modify, or delete data beyond what is necessary
3. **Maintain confidentiality** - Do not disclose the vulnerability publicly until coordinated
4. **Act in good faith** - Conduct research within legal boundaries
5. **No extortion** - Do not demand payment for non-disclosure

### 6.2 What Constitutes Good Faith

- Testing against your own installations or test environments
- Stopping testing upon discovery of sensitive data
- Not performing denial of service attacks
- Not accessing systems or data beyond what is necessary to demonstrate the vulnerability

"""

        if cfg.safe_harbor:
            policy += """---

## 7. Safe Harbor

{org} will not pursue legal action against researchers who:

- Follow this policy and act in good faith
- Report vulnerabilities through authorized channels
- Avoid actions that could harm users or systems
- Do not publicly disclose before coordinated disclosure

We consider security research conducted under this policy to be:
- Authorized concerning any applicable anti-hacking laws
- Authorized concerning any applicable anti-circumvention laws
- Exempt from restrictions in our Terms of Service that would interfere
  with conducting security research

""".format(org=cfg.organization_name or "[Organization Name]")

        if cfg.hall_of_fame or cfg.bug_bounty:
            policy += """---

## 8. Recognition

"""
            if cfg.hall_of_fame:
                policy += """### 8.1 Hall of Fame

We maintain a Hall of Fame to recognize researchers who have responsibly
disclosed vulnerabilities. With your permission, we will include:

- Your name or handle
- A link to your website or profile
- The nature of your contribution

"""
            if cfg.bug_bounty:
                policy += f"""### 8.2 Bug Bounty Program

We offer monetary rewards for qualifying vulnerability reports.
See our bug bounty program for details: [{cfg.bug_bounty_url}]({cfg.bug_bounty_url})

"""

        policy += f"""---

## 9. Contact and Questions

For questions about this policy or the vulnerability disclosure process:

**Email:** [{cfg.security_email}](mailto:{cfg.security_email})
"""
        if cfg.legal_contact:
            policy += f"""**Legal Inquiries:** {cfg.legal_contact}
"""

        policy += f"""
---

## 10. Policy Updates

This policy may be updated periodically. The current version is always
available at: {cfg.organization_website or "[Organization Website]"}/security

**Last Updated:** {now}

---

## Appendix A: FDA Compliance Statement

This Coordinated Vulnerability Disclosure policy has been established in
accordance with FDA Cybersecurity Guidance (June 2025), which requires
medical device manufacturers to:

- Establish and document a CVD policy
- Provide a mechanism for receiving vulnerability reports
- Define timelines for acknowledgment and remediation
- Maintain records of vulnerabilities and remediation actions

For FDA premarket submissions, this policy document should be included
in the cybersecurity documentation package.

---

*This policy template was generated by DICOM Fuzzer for FDA cybersecurity compliance.*
"""
        return policy

    def generate_policy_json(self) -> dict[str, Any]:
        """Generate CVD policy configuration as JSON."""
        cfg = self.config
        return {
            "policy_version": "1.0",
            "effective_date": datetime.now(UTC).isoformat(),
            "organization": {
                "name": cfg.organization_name,
                "website": cfg.organization_website,
                "product": cfg.product_name,
            },
            "contact": {
                "email": cfg.security_email,
                "pgp_key": cfg.security_pgp_key,
                "portal_url": cfg.security_portal_url,
            },
            "timelines": {
                "acknowledgment_days": cfg.acknowledgment_deadline,
                "initial_assessment_days": cfg.initial_assessment_deadline,
                "remediation_target_days": cfg.remediation_target,
                "public_disclosure_days": cfg.public_disclosure_deadline,
            },
            "scope": {
                "in_scope": cfg.in_scope_products,
                "out_of_scope": cfg.out_of_scope,
            },
            "recognition": {
                "hall_of_fame": cfg.hall_of_fame,
                "bug_bounty": cfg.bug_bounty,
                "bug_bounty_url": cfg.bug_bounty_url,
            },
            "legal": {
                "safe_harbor": cfg.safe_harbor,
                "contact": cfg.legal_contact,
            },
        }

    def save_policy(self, output_path: Path | str, format: str = "markdown") -> Path:
        """Save CVD policy to file.

        Args:
            output_path: Output file path
            format: Output format ('markdown' or 'json')

        Returns:
            Path to saved file

        """
        import json

        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        if format == "json":
            with open(output_path, "w") as f:
                json.dump(self.generate_policy_json(), f, indent=2)
        else:
            output_path.write_text(self.generate_policy_markdown())

        return output_path


def generate_cvd_policy(
    organization: str = "",
    product: str = "",
    security_email: str = "security@example.com",
    output_path: Path | str | None = None,
) -> str:
    """Generate a CVD policy with minimal configuration.

    Args:
        organization: Organization name
        product: Product name
        security_email: Security contact email
        output_path: Optional path to save the policy

    Returns:
        Policy content as string

    """
    config = CVDPolicyConfig(
        organization_name=organization,
        product_name=product,
        security_email=security_email,
    )

    generator = CVDPolicyGenerator(config)
    policy = generator.generate_policy_markdown()

    if output_path:
        generator.save_policy(output_path)

    return policy


if __name__ == "__main__":
    # Generate sample policy
    config = CVDPolicyConfig(
        organization_name="Medical Device Corp",
        organization_website="https://www.meddevicecorp.com",
        product_name="DICOM Viewer Pro",
        security_email="security@meddevicecorp.com",
        in_scope_products=[
            "DICOM Viewer Pro v2.x and later",
            "DICOM Viewer Mobile App",
            "DICOM Gateway Service",
        ],
    )

    generator = CVDPolicyGenerator(config)
    print(generator.generate_policy_markdown())
