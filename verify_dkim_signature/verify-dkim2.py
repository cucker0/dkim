"""
验证 multipart/alternative 类型的邮件的 DKIM 签名


验证 DKIM 签名时，意邮件 DKIM-Signature 中的 x=17xx 字段，这是过期时间（时间戳）。
进行验证DKIM签名时，需要注意时间未过期。
测试时，可以手动调整本地的时间，以确保时间未过期。
"""

import dkim
from email.parser import Parser

if __name__ == '__main__':
    # get message from a email file. type is Message
    msg = Parser().parsestr(open("./Gmail_to_QQ_mail.eml", "r").read())
    message = msg.as_bytes()
    ret = dkim.verify(message)
    print(ret)
