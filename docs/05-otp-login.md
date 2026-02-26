# 05. OTP login

## Métodos SDK
- `request_otp_login(RequestOtpRequest) -> RequestOtpResponse`
- `login_with_otp(OtpLoginRequest) -> OtpLoginResponse`

## Paso 1
`RequestOtpRequest { email, metadata }`

`RequestOtpResponse`:
- `success`
- `message`
- `email_sent_to`
- `expires_at`
- `expires_in_minutes`

## Paso 2
`OtpLoginRequest { email, code }`

`OtpLoginResponse`:
- `jwt`, `expires_in`
- `user`, `company`, `session`, `application`
- `metadata`
