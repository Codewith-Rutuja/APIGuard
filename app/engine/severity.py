SEVERITY_LEVELS = {
    "Critical": 4,
    "High": 3,
    "Medium": 2,
    "Low": 1,
    "Informational": 0,
}


def classify_severity(
    exploitability,
    data_sensitivity,
    authorization_impact,
):
    score = (
        exploitability
        + data_sensitivity
        + authorization_impact
    )

    if score >= 8:
        return "Critical"

    if score >= 6:
        return "High"

    if score >= 4:
        return "Medium"

    if score >= 2:
        return "Low"

    return "Informational"
