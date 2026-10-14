# 04. Email verification

## SDK methods
- `request_email_verification(RequestEmailVerificationRequest) -> RequestEmailVerificationResponse`
- `verify_email(VerifyEmailRequest) -> bool`
- `resend_verification(ResendVerificationRequest) -> bool`

## Models
- `RequestEmailVerificationRequest { user_id, email, language }`
- `RequestEmailVerificationResponse { success, message }`. The code is only ever emailed; the API never returns it. The response is identical whether or not a code was issued (unknown user, email mismatch, already verified).
- `VerifyEmailRequest { verification_code, user_id, language }`
- `ResendVerificationRequest { user_id, email, language }`

The SDK adds `company_id` (and `application_id` where the endpoint needs it) from the configuration. `verify_email` and `resend_verification` return `false` when the server rejects the request and an error only for transport failures.

- `verify_email`: a wrong, expired or unknown code, and a verification burned after 5 failed attempts, all get the same `422` (`false`). Request a new code with `resend_verification`.
- `resend_verification`: the server answers the same whether or not a code was sent, so `true` means "accepted", not "sent".

## Endpoints
- `POST /v1/public/request-email-verification`
- `POST /v1/public/verify-email`
- `POST /v1/public/resend-verification`
