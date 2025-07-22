def map_cvss_score_to_severity(score: float) -> str:
    """
    Map CVSS score to severity level.
    """
    if score < 0 or score > 10:
        return "Unknown"
    if score == 0.0:
        return "None"
    elif score <= 3.9:
        return "Low"
    elif score <= 6.9:
        return "Medium"
    elif score <= 8.9:
        return "High"
    else:
        return "Critical"


def map_cve_impact_to_severity(impact_str: str) -> str:
    """
    Map CVE impact strings (like 'HIGH', 'MEDIUM') to normalized severity.
    """
    impact = impact_str.lower()
    if "critical" in impact:
        return "Critical"
    elif "high" in impact:
        return "High"
    elif "medium" in impact:
        return "Medium"
    elif "low" in impact:
        return "Low"
    elif "none" in impact:
        return "None"
    else:
        return "Unknown"
