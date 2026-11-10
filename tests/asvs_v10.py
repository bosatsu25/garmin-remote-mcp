"""OWASP ASVS 5.0.0, chapter V10 (OAuth and OIDC): checklist for checklist-based testing
(JSTQB FL §4.4.3).

Every requirement of the chapter is listed with its level and one of:
  covered         tests that verify it (enforced to exist by tests/test_asvs_checklist.py)
  not_applicable  with the reason
  not_targeted    Level 3; this server targets Level 2

Requirement texts: https://github.com/OWASP/ASVS/tree/v5.0.0/5.0 (CC BY-SA 4.0).
IDs and levels were generated from the official 5.0.0 JSON release.
"""

from __future__ import annotations

from typing import NamedTuple


class Item(NamedTuple):
    level: int
    status: str
    tests: tuple[str, ...]
    note: str


TARGET_LEVEL = 2

V10: dict[str, Item] = {
    "V10.1.1": Item(2, "covered", (
        "tests/integration/test_mcp_tools.py::test_errors_never_leak_tokens",
        "tests/integration/test_oauth_http.py::test_token_in_query_string_is_not_accepted",
        "tests/unit/test_garmin_client.py::test_login_is_token_only",
    ), "Garmin tokens never leave the server; MCP tokens go only to the client that redeemed the code."),
    "V10.1.2": Item(2, "not_applicable", (
    ), "Requirement on the OAuth client. The client here is claude.ai; this server is the authorization server and resource server."),
    "V10.2.1": Item(2, "not_applicable", (
    ), "Requirement on the OAuth client. The client here is claude.ai; this server is the authorization server and resource server."),
    "V10.2.2": Item(2, "not_applicable", (
    ), "Requirement on the OAuth client. The client here is claude.ai; this server is the authorization server and resource server."),
    "V10.2.3": Item(3, "not_applicable", (
    ), "Requirement on the OAuth client. The client here is claude.ai; this server is the authorization server and resource server."),
    "V10.3.1": Item(2, "covered", (
        "tests/integration/test_asvs_v10.py::test_v10_3_1_token_for_another_audience_is_refused",
        "tests/integration/test_asvs_v10.py::test_v10_3_1_audience_is_stored_per_token",
    ), ""),
    "V10.3.2": Item(2, "covered", (
        "tests/integration/test_mcp_tools.py::test_dt_rule1_write_enabled_and_granted",
        "tests/integration/test_mcp_tools.py::test_dt_rule2_write_enabled_but_read_only_grant",
        "tests/integration/test_mcp_tools.py::test_dt_rule3_write_disabled_even_with_forged_write_scope",
    ), ""),
    "V10.3.3": Item(2, "not_applicable", (
    ), "There is exactly one resource owner; no access decision distinguishes users."),
    "V10.3.4": Item(2, "not_applicable", (
    ), "The resource server has no authentication-strength or recentness requirement."),
    "V10.3.5": Item(3, "not_targeted", (
    ), "Level 3 requirement; the target for this single-owner server is Level 2."),
    "V10.4.1": Item(1, "covered", (
        "tests/integration/test_asvs_v10.py::test_v10_4_1_redirect_uri_is_compared_exactly",
        "tests/integration/test_asvs_v10.py::test_v10_4_1_equivalent_spellings_still_land_on_the_registered_uri",
        "tests/integration/test_oauth_http.py::test_redirect_uri_must_match_at_token",
        "tests/unit/test_redirect_policy.py::test_fault_attacks_rejected",
    ), "Deviation: the SDK compares normalized URLs, not raw strings; accepted spellings are proven to redirect to the registered URI."),
    "V10.4.2": Item(1, "covered", (
        "tests/integration/test_asvs_v10.py::test_v10_4_2_replayed_code_revokes_tokens_it_issued",
        "tests/integration/test_asvs_v10.py::test_v10_4_2_replay_without_pkce_verifier_still_revokes",
        "tests/integration/test_asvs_v10.py::test_v10_4_2_concurrent_double_redemption",
        "tests/integration/test_asvs_v10.py::test_v10_4_2_reuse_window_boundary",
    ), ""),
    "V10.4.3": Item(1, "covered", (
        "tests/unit/test_oauth_provider.py::test_code_ttl_boundary",
    ), "Lifetime is 5 minutes (limit: 10)."),
    "V10.4.4": Item(1, "covered", (
        "tests/integration/test_asvs_v10.py::test_v10_4_4_clients_can_only_register_needed_grants",
        "tests/integration/test_exploratory_findings.py::test_unsupported_grant_types_never_issue_tokens",
    ), ""),
    "V10.4.5": Item(1, "covered", (
        "tests/unit/test_oauth_provider.py::test_refresh_reuse_revokes_entire_family",
        "tests/integration/test_oauth_http.py::test_refresh_reuse_over_http_revokes_family",
        "tests/unit/test_oauth_provider.py::test_reuse_detection_survives_restart",
    ), "Refresh token rotation with reuse detection (the L1/L2 option)."),
    "V10.4.6": Item(2, "covered", (
        "tests/integration/test_asvs_v10.py::test_v10_4_6_code_challenge_is_mandatory",
        "tests/integration/test_asvs_v10.py::test_v10_4_6_code_verifier_is_mandatory",
        "tests/integration/test_oauth_http.py::test_authorize_requires_pkce_s256",
        "tests/integration/test_oauth_http.py::test_wrong_pkce_verifier_rejected",
    ), ""),
    "V10.4.7": Item(2, "covered", (
        "tests/integration/test_oauth_http.py::test_dcr_rejects_bad_redirects",
        "tests/unit/test_oauth_provider.py::test_client_name_length_boundary",
        "tests/integration/test_asvs_v10.py::test_v10_7_2_consent_page_says_what_who_and_how_long",
        "tests/integration/test_oauth_http.py::test_consent_page_escapes_client_name",
    ), ""),
    "V10.4.8": Item(2, "covered", (
        "tests/unit/test_oauth_provider.py::test_family_max_age_caps_rotation",
        "tests/unit/test_oauth_provider.py::test_refresh_token_ttl_boundary",
    ), "Absolute lifetime of a grant: 90 days."),
    "V10.4.9": Item(2, "covered", (
        "tests/integration/test_asvs_v10.py::test_v10_4_9_owner_lists_and_revokes_one_connection",
        "tests/integration/test_asvs_v10.py::test_v10_4_9_connections_page_requires_passphrase",
        "tests/integration/test_asvs_v10.py::test_v10_4_9_revoke_needs_valid_session",
        "tests/integration/test_asvs_v10.py::test_v10_4_9_admin_session_ttl_boundary",
    ), ""),
    "V10.4.10": Item(2, "covered", (
        "tests/integration/test_asvs_v10.py::test_v10_4_10_confidential_client_must_authenticate",
    ), ""),
    "V10.4.11": Item(2, "covered", (
        "tests/integration/test_oauth_http.py::test_granted_scope_follows_consent_checkbox",
        "tests/integration/test_oauth_http.py::test_refresh_cannot_add_write_scope",
        "tests/unit/test_oauth_provider.py::test_client_scope_registration",
    ), ""),
    "V10.4.12": Item(3, "not_targeted", (
    ), "Level 3 requirement; the target for this single-owner server is Level 2."),
    "V10.4.13": Item(3, "not_targeted", (
    ), "Level 3 requirement; the target for this single-owner server is Level 2."),
    "V10.4.14": Item(3, "not_targeted", (
    ), "Level 3 requirement; the target for this single-owner server is Level 2."),
    "V10.4.15": Item(3, "not_targeted", (
    ), "Level 3 requirement; the target for this single-owner server is Level 2."),
    "V10.4.16": Item(3, "not_targeted", (
    ), "Level 3 requirement; the target for this single-owner server is Level 2."),
    "V10.5.1": Item(2, "not_applicable", (
    ), "Requirement on an OIDC relying party. This server consumes no ID Tokens."),
    "V10.5.2": Item(2, "not_applicable", (
    ), "Requirement on an OIDC relying party. This server consumes no ID Tokens."),
    "V10.5.3": Item(2, "not_applicable", (
    ), "Requirement on an OIDC relying party. This server consumes no ID Tokens."),
    "V10.5.4": Item(2, "not_applicable", (
    ), "Requirement on an OIDC relying party. This server consumes no ID Tokens."),
    "V10.5.5": Item(2, "not_applicable", (
    ), "Requirement on an OIDC relying party. This server consumes no ID Tokens."),
    "V10.6.1": Item(2, "not_applicable", (
    ), "Requirement on an OpenID Provider. This server issues no ID Tokens and has no logout endpoint."),
    "V10.6.2": Item(2, "not_applicable", (
    ), "Requirement on an OpenID Provider. This server issues no ID Tokens and has no logout endpoint."),
    "V10.7.1": Item(2, "covered", (
        "tests/integration/test_asvs_v10.py::test_v10_7_1_every_authorization_request_needs_fresh_consent",
        "tests/integration/test_oauth_http.py::test_request_id_is_single_use",
    ), ""),
    "V10.7.2": Item(2, "covered", (
        "tests/integration/test_asvs_v10.py::test_v10_7_2_consent_page_says_what_who_and_how_long",
        "tests/integration/test_oauth_http.py::test_consent_page_offers_write_only_when_enabled",
    ), ""),
    "V10.7.3": Item(2, "covered", (
        "tests/integration/test_asvs_v10.py::test_v10_7_3_owner_revokes_everything",
        "tests/integration/test_asvs_v10.py::test_v10_4_9_owner_lists_and_revokes_one_connection",
    ), "Review and revoke are provided; to modify a grant the owner revokes it and reconnects."),
}
