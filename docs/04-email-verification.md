# 04. Email verification

## SDK methods
- `request_email_verification(RequestEmailVerificationRequest) -> RequestEmailVerificationResponse`
- `verify_email(VerifyEmailRequest) -> bool`
- `resend_verification(ResendVerificationRequest) -> bool`

## Models
- `RequestEmailVerificationRequest { user_id, email, language }`
- `RequestEmailVerificationResponse { success, message, verification_id }`. The code is only ever emailed; the API never returns it.
- `VerifyEmailRequest { verification_code, user_id, language }`
- `ResendVerificationRequest { user_id, email, language }`

The SDK adds `company_id` (and `application_id` where the endpoint needs it) from the configuration. `verify_email` and `resend_verification` return `false` when the server rejects the request and an error only for transport failures.

## Endpoints
- `POST /v1/public/request-email-verification`
- `POST /v1/public/verify-email`
- `POST /v1/public/resend-verification`
