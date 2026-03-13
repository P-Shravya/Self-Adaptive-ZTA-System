RESOURCE_SENSITIVITY = {
    "/api/login": 0.2,
    "/api/dashboard": 0.5,
    "/api/profile": 0.3,
    "/api/reports": 0.6,
    "/api/finance": 0.8,
    "/api/payroll": 0.9,
    "/api/admin": 0.95,

    # Section APIs (these are real routers in your app)
    # Setting these lets StepUpEngine trigger on section access, not only admin.
    "/api/pharmacy": 0.7,
    "/api/lab": 0.75,
    "/api/approvals": 0.85,
    "/api/doctors": 0.6
}

ROLE_MULTIPLIER = {
    "admin": 1.2,
    "manager": 1.0,
    "employee": 0.9
}

def get_resource_sensitivity(resource, role):
    base = RESOURCE_SENSITIVITY.get(resource, 0.2)
    multiplier = ROLE_MULTIPLIER.get(role, 1.0)
    return min(base * multiplier, 1.0)

# backend/security/resource_policy.py

ROLE_ACCESS = {
    "admin": [
        "/api/admin",
        "/api/dashboard",
        "/api/pharmacy",
        "/api/lab",
        "/api/doctors"       # admin can access doctors section
    ],
    "manager": [
        "/api/approvals",    # ONLY manager has this
        "/api/dashboard"
    ],
    "doctor": [
        "/api/dashboard",
        "/api/lab",
        "/api/doctors"       # doctor can access doctors section
    ],
    "pharmacist": [
        "/api/pharmacy",
        "/api/dashboard"
    ],
    "nurse": [
        "/api/dashboard"
    ],
    "employee": [
        "/api/dashboard"
    ]
}

def has_access(role: str, resource: str):

    allowed = ROLE_ACCESS.get(role, [])

    for path in allowed:
        if resource.startswith(path):
            return True

    return False