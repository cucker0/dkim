import smtplib, dkim, time, os

from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText


print('Content-Type: text/plain')
print('')
msg = MIMEMultipart('alternative')
msg['From'] = 'test@example.com'
msg['To'] = 'person@anotherexample.com'
msg['Subject'] = ' Test Subject'
msg['Message-ID'] = "<" + str(time.time()) + "-1234567890@example.com" + ">"

# Create the body of the message (a plain-text and an HTML version).
text = """\
Test email displayed as text only
"""

html = """\
<!doctype html>
<html xmlns="http://www.w3.org/1999/xhtml" xmlns:v="urn:schemas-microsoft-com:vml" xmlns:o="urn:schemas-microsoft-com:office:office">
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
private_key = open(os.path.join(os.path.abspath(os.path.dirname(__file__)), 'verify_dkim_signature/private.pem')).read()

# Specify headers in "byte" form
headers=[b'from', b'to', b'subject', b'message-id']

# Generate message signature
sig = dkim.sign(msg.as_bytes(), b'introduction', b'example.com', private_key.encode(), include_headers=headers)
sig = sig.decode()

# Add the DKIM-Signature
msg['DKIM-Signature'] = sig[len("DKIM-Signature: "):]

# print(msg)

# Send the message via local SMTP server.
s = smtplib.SMTP('localhost')
# sendmail function takes 3 arguments: sender's address, recipient's address
# and message to send - here it is sent as one string.
s.sendmail(msg['From'], msg['To'], msg.as_string())
s.quit()