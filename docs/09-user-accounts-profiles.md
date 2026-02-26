# 09. User accounts y profiles

## Accounts
- `get_account(token, account_id) -> FullUserAccountResponse`
- `update_account(token, account_id, UpdateUserAccountRequest) -> UserAccountResponse`
- `soft_delete_account(token, account_id) -> OperationResponse`
- `restore_account(token, account_id) -> OperationResponse`
- `hard_delete_account(token, account_id) -> OperationResponse`

## Profiles
- `get_profile(token, profile_id) -> UserProfileResponse`
- `search_profile_by_email(token, email) -> UserProfileResponse`
- `update_profile(token, profile_id, UpdateUserProfileRequest) -> UserProfileResponse`
- `delete_profile(token, profile_id) -> OperationResponse`

## Endpoints
El SDK apunta a `/v1/user-accounts/...` y `/v1/user-profiles/...`; normalmente se consumen bajo scope master en backend actual.
