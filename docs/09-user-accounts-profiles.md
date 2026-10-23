# 09. User accounts and profiles (master)

These routes live under the master scope: `token` must be a **master** access token.

## Accounts
- `get_account(token, account_id) -> FullUserAccountResponse`: `GET /v1/master/user-accounts/{id}`
- `update_account(token, account_id, UpdateUserAccountRequest) -> UserAccountResponse`: `PATCH /v1/master/user-accounts/{id}`
- `soft_delete_account(token, account_id) -> OperationResponse`: `POST /v1/master/user-accounts/{id}/soft-delete`
- `restore_account(token, account_id) -> OperationResponse`: `POST /v1/master/user-accounts/{id}/restore`
- `hard_delete_account(token, account_id) -> OperationResponse`: `DELETE /v1/master/user-accounts/{id}`

An account carries no role: what a person may do in an application is a role assignment in an
organization (`AssignmentsClient`), never a field of the account.

## Profiles
- `get_profile(token, profile_id) -> UserProfileResponse`: `GET /v1/master/user-profiles/{id}`
- `search_profile_by_email(token, email) -> UserProfileResponse`: `GET /v1/master/user-profiles/search?email=`
- `update_profile(token, profile_id, UpdateUserProfileRequest) -> UserProfileResponse`: `PATCH /v1/master/user-profiles/{id}`
- `delete_profile(token, profile_id) -> OperationResponse`: `DELETE /v1/master/user-profiles/{id}`

Before 0.5.0 the SDK called `/v1/user-accounts/...` and `/v1/user-profiles/...`, which the server does not mount (404).
