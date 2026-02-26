# 12. Multi-tenant

Requiere feature `multi-tenant`.

## Trait
`MultiTenantExt` agrega métodos con `company_id` dinámico:
- `login_with_company`
- `register_with_company`
- `verify_email_with_company`
- `request_password_reset_with_company`
- `verify_reset_code_with_company`
- `complete_password_reset_with_company`
- `complete_password_reset_with_token_with_company`
- `login_with_oauth_with_company`

## Caso de uso
Cuando una sola aplicación integra múltiples tenants y el `company_id` cambia por usuario/request.
