# Future Enhancements – Authentication Service

This document outlines planned improvements and future enhancements for the authentication microservice.

## Account State & Access Control
- The `is_active` flag is currently not used during the login flow (`login_for_access_token`) or anywhere else. Determine whether this field should restrict authentication attempts. Client applications may require APIs to modify this flag, though it currently has no functional effect.

## Security & Token Management
- Assess whether the `GET /auth/public-key` endpoint can be removed. Ideally, clients should not need to extract or inspect bearer tokens, improving overall security posture.

## User Self-Service Features
- Implement an endpoint that allows users to change their own passwords securely.

## Permissions System
- Permissions such as `["read:posts", "write:posts"]` need standardized definitions from upstream services. The authentication service should treat permissions as opaque strings—store and retrieve only, without validation.
- Verify if there is an existing endpoint that allows users to retrieve their own permissions. Add one if missing.

## Login Security & Abuse Prevention
- Introduce rate limiting for failed login attempts. Track failed attempts per user and, after *N* consecutive failures, temporarily lock the account (e.g., for 24 hours) or require an admin-initiated password reset.

## Administrative Capabilities
 - Add admin-focused APIs or a simple dashboard for managing users, roles, and permissions.

## Password Policy
- Enforce a minimal password policy (minimum length and basic complexity).

## Audit Logging
- Record key authentication and account events and provide a secure way to retrieve audit logs.
