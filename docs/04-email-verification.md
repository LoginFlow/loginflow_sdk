# 04. Email verification

## Métodos SDK
- `verify_email(VerifyEmailRequest) -> bool`
- `resend_verification(ResendVerificationRequest) -> bool`

## Request models
- `VerifyEmailRequest { verification_code, user_id }`
- `ResendVerificationRequest { user_id, email }`

El SDK agrega `company_id` y `application_id` desde configuración.

## Endpoints
- `POST /v1/public/verify-email`
- `POST /v1/public/resend-verification`
