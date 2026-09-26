OWASP_API_2023 = {
    "API1": {
        "id": "API1:2023",
        "name": "Broken Object Level Authorization",
    },
    "API2": {
        "id": "API2:2023",
        "name": "Broken Authentication",
    },
    "API3": {
        "id": "API3:2023",
        "name": "Broken Object Property Level Authorization",
    },
    "API4": {
        "id": "API4:2023",
        "name": "Unrestricted Resource Consumption",
    },
    "API5": {
        "id": "API5:2023",
        "name": "Broken Function Level Authorization",
    },
    "API6": {
        "id": "API6:2023",
        "name": "Unrestricted Access to Sensitive Business Flows",
    },
    "API7": {
        "id": "API7:2023",
        "name": "Server Side Request Forgery",
    },
    "API8": {
        "id": "API8:2023",
        "name": "Security Misconfiguration",
    },
    "API9": {
        "id": "API9:2023",
        "name": "Improper Inventory Management",
    },
    "API10": {
        "id": "API10:2023",
        "name": "Unsafe Consumption of APIs",
    },
}


def get_category(key):
    return OWASP_API_2023.get(key)
