"""Offline acceptance fixture for the deployed security-review pipeline.

This file is not imported by the scanner or deployed as an application.
It contains no credentials, network calls, or executable target payloads.
"""


def visible_records(records, organization_id):
    """Select records belonging to the authenticated caller's organization."""
    if not organization_id:
        raise ValueError("An authenticated organization is required")
    return [
        {"id": record["id"], "name": record["name"]}
        for record in records
        if record["organization_id"] == organization_id
    ]


def test_organization_boundary():
    # Check both visible and cross-organization records without network access.
    records = [
        {"id": "one", "name": "Visible", "organization_id": "org-a"},
        {"id": "two", "name": "Other tenant", "organization_id": "org-b"},
    ]
    assert visible_records(records, "org-a") == [{"id": "one", "name": "Visible"}]
    assert visible_records(records, "org-c") == []


if __name__ == "__main__":
    test_organization_boundary()
