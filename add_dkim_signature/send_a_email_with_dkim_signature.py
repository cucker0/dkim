"""
生成一封包含 DKIM 签名 Email,
模拟 MTA(Mail Transfer Agent) 发送邮件到 Gmail

"""

import smtplib, dkim, time, os

from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import dns.resolver

from email.message import Message

def generate_email():
    """ Generate a email

    return: Message
        message of a full maill
    """
    msg = MIMEMultipart('alternative')
    msg['From'] = 'lisa@cucker.top'
    msg['To'] = 'hanxiao2100@gmail.com'
    msg['Subject'] = 'A DKIM mail'
    msg['Message-ID'] = "<" + str(time.time()) + "-lisa@cucker.top" + ">"

    # Create the body of the message (a plain-text and an HTML version).
    text = """\
Test email displayed as text only
"""

    html = """\
<!doctype html>
<html>
<head>
    <title>Test DKMI Email</title>
</head>

<body>
    HTML Body of Test DKIM
</body>
</html>
"""

    # Record the MIME types of both parts - text/plain and text/html.
    part1 = MIMEText(text, 'plain')
    part2 = MIMEText(html, 'html')

    msg.attach(part1)
    msg.attach(part2)

    # DKIM Private Key for example.com RSA-2048bit
    private_key = open(os.path.join(os.path.abspath(os.path.dirname(__file__)), 'private.pem')).read()

    # Specify headers in "byte" form
    headers=[b'from', b'to', b'subject', b'message-id']

    # Generate message signature
    sig = dkim.sign(message=msg.as_bytes(), selector=b's20240725', domain=b'cucker.top', privkey=private_key.encode(),
                    canonicalize=(b'relaxed', b'simple'), signature_algorithm=b'rsa-sha256',
                    include_headers=headers)
    sig = sig.decode()

    # Add the DKIM-Signature
    msg['DKIM-Signature'] = sig[len("DKIM-Signature: "):]

    # print(msg)
    return msg

def smtp_sendmail(msg: Message):
    """ Send the message via a SMTP server.

    msg: Message
        the message to be sent
    return: None
    """
    to_domain = str(msg.get('To')).split('@')[1]
    mx_set = dns.resolver.resolve(to_domain, 'MX')
    if len(mx_set) <= 0:
        print('No Mail exchanger found for destination')
        exit(1)
    else:
        mx_server = mx_set[0].exchange.to_text()

    smtp_connection = smtplib.SMTP(host=mx_server, port=25)
    smtp_connection.ehlo()
    smtp_connection.starttls()  # 启用TLS

    # sendmail function takes 3 arguments: sender's address, recipient's address
    # and message to send - here it is sent as one string.
    smtp_connection.debuglevel = 1
    smtp_connection.sendmail(msg['From'], msg['To'], msg.as_string())
    smtp_connection.quit()

if __name__ == '__main__':
    msg = generate_email()
    smtp_sendmail(msg)