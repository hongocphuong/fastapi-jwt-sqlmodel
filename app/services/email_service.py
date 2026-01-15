from app.core.config import settings

# DEV: in-console; PROD: tích hợp SMTP/Provider (SendGrid, Mailgun...) tại đây
async def send_email(to_email: str, subject: str, html_body: str):
    if not settings.SMTP_HOST:
        print("===== EMAIL (DEV) =====")
        print("To:", to_email)
        print("Subject:", subject)
        print("Body:\n", html_body)
        print("=======================")
        return
    # TODO: SMTP send (aiosmtplib/smtplib) hoặc SDK nhà cung cấp
    raise NotImplementedError("SMTP sending not implemented in this scaffold")
