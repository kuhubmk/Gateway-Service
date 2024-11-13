import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from src.core.config import settings
import logging

logger = logging.getLogger(__name__)

async def send_email(to_email: str, subject: str, body: str):
    """发送邮件的通用方法"""
    try:
        # 创建邮件内容
        msg = MIMEMultipart()
        msg['From'] = settings.sender_email
        msg['To'] = to_email
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'html', 'utf-8'))

        # 使用 SSL 连接发送邮件
        server = smtplib.SMTP_SSL(settings.smtp_server, settings.smtp_port)
        server.login(settings.sender_email, settings.password)
        server.sendmail(settings.sender_email, to_email, msg.as_string())
        server.quit()
            
        logger.info(f"Email sent successfully to {to_email}")
        
    except Exception as e:
        logger.error(f"Error sending email: {str(e)}")
        raise

async def send_verification_email(to_email: str, token: str):
    """发送邮箱验证邮件"""
    verify_url = f"{settings.FRONTEND_URL}/verify-email?token={token}"
    subject = "验证您的邮箱"
    body = f"""
    <html>
        <body>
            <h2>邮箱验证</h2>
            <p>您好，</p>
            <p>请点击下面的链接验证您的邮箱：</p>
            <p><a href="{verify_url}">{verify_url}</a></p>
            <p>此链接24小时内有效。</p>
            <p>如果您没有注册账号，请忽略此邮件。</p>
        </body>
    </html>
    """
    await send_email(to_email, subject, body)

async def send_reset_password_email(to_email: str, token: str):
    """发送密码重置邮件"""
    reset_url = f"{settings.FRONTEND_URL}/reset-password?token={token}"
    subject = "密码重置请求"
    body = f"""
    <html>
        <body>
            <h2>密码重置</h2>
            <p>您好，</p>
            <p>您请求重置密码。请点击下面的链接重置密码：</p>
            <p><a href="{reset_url}">{reset_url}</a></p>
            <p>此链接24小时内有效。</p>
            <p>如果您没有请求重置密码，请忽略此邮件。</p>
        </body>
    </html>
    """
    await send_email(to_email, subject, body)