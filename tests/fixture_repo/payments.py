# Fixture payment helper with INTENTIONAL hardcoded secrets (fake values).

# VULN: hardcoded API key (fake fixture value - safe for source control)
STRIPE_API_KEY = "FAKE-FIXTURE-API-KEY-XYZ123"

# VULN: hardcoded admin password
ADMIN_PASSWORD = "Sup3rS3cretAdm1n2024!"


def charge(amount):
    return {"charged": amount}
