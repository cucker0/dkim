"""
手动验证 DKIM 签名

"""
import hashlib
import re
import time

import dkim
from email.parser import BytesParser

from Crypto.PublicKey import RSA
from dkim import CanonicalizationPolicy, InvalidCanonicalizationPolicyError, RSASSA_PKCS1_v1_5_verify, parse_public_key
from dkim.crypto import str2int, int2str, EMSA_PKCS1_v1_5_encode, rsa_encrypt, UnparsableKeyError
from dkim.util import InvalidTagSpec, DuplicateTag
from Crypto.Signature import PKCS1_v1_5 as Signature_pkcs1_v1_5

import base64

from setuptools.config._validate_pyproject import ValidationError


# #: Header fields to protect from additions by default.
# #:
# #: The short list below is the result more of instinct than logic.
# #: @since: 0.5
# FROZEN = (b'from',)
#
# #: The rfc6376 recommended header fields to sign
# #: @since: 0.5
# SHOULD = (
# b'from', b'sender', b'reply-to', b'subject', b'date', b'message-id', b'to', b'cc',
# b'mime-version', b'content-type', b'content-transfer-encoding',
# b'content-id', b'content-description', b'resent-date', b'resent-from',
# b'resent-sender', b'resent-to', b'resent-cc', b'resent-message-id',
# b'in-reply-to', b'references', b'list-id', b'list-help', b'list-unsubscribe',
# b'list-subscribe', b'list-post', b'list-owner', b'list-archive'
# )
#
# #: The rfc6376 recommended header fields not to sign.
# #: @since: 0.5
# SHOULD_NOT = (
# b'return-path',b'received',b'comments',b'keywords',b'bcc',b'resent-bcc',
# b'dkim-signature'
# )
#
# # Doesn't seem to be used (GS)
# #: The U{RFC5322<http://tools.ietf.org/html/rfc5322#section-3.6>}
# #: complete list of singleton headers (which should
# #: appear at most once).  This can be used for a "paranoid" or
# #: "strict" signing mode.
# #: Bcc in this list is in the SHOULD NOT sign list, the rest could
# #: be in the default FROZEN list, but that could also make signatures
# #: more fragile than necessary.
# #: @since: 0.5
# RFC5322_SINGLETON = (b'date',b'from',b'sender',b'reply-to',b'to',b'cc',b'bcc',
#     b'message-id',b'in-reply-to',b'references')


def get_dns_txt(name: str) -> bytes:
    """ 获取指定 name 的 DNS TXT记录值

    @param name: str
        要查询的 DNS name，类型为 DNS TXT
    @return: str
        DNS TXT 记录的值
    """
    import dns.resolver
    a = dns.resolver.resolve(name, 'TXT')
    if a:
        a_txt:str = a[0].to_text()
        return a_txt.encode('ascii')

def get_dkim_txt(name: str):
    """

    @param name: 获取指定 name 的 DNS TXT记录值
    @return: dict
        dkim 记录的值处理后的值.
        格式示例：{'v': 'DKIM1', 'k': 'rsa', 'p':'xxx'}
    """
    txt_val = get_dns_txt(name).strip(b'"').replace(b'" "', b'')
    d = {}
    li = txt_val.split(b';')
    for i in li:
        i = i.strip()
        if i.startswith(b'v='):
            d[b'v'] = i.split(b'=')[1]
        elif i.startswith(b'k='):
            d[b'k'] = i.split(b'=')[1]
        elif i.startswith(b'p='):
            d[b'p'] = i.split(b'=')[1]
        else:
            pass
    return d

HASH_ALGORITHMS = {
    b'rsa-sha1': hashlib.sha1,
    b'rsa-sha256': hashlib.sha256,
    b'ed25519-sha256': hashlib.sha256
    }

ARC_HASH_ALGORITHMS = {
    b'rsa-sha256': hashlib.sha256,
    }

def timestamp_format(timestamp: int):
    """ 时间戳格式化

    @param timestamp:
    @return:
    """
    formatted_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(timestamp))
    return formatted_time

def validate_signature_fields(sig, mandatory_fields=[b'v', b'a', b'b', b'bh', b'd', b'h', b's'], arc=False):
    """Validate DKIM or ARC Signature fields.
    Basic checks for presence and correct formatting of mandatory fields.
    Raises a ValidationError if checks fail, otherwise returns None.
    @param sig: A dict mapping field keys to values.
    @param mandatory_fields: A list of non-optional fields. 必选的字段
    @param arc: flag to differentiate between dkim & arc
    """
    if arc:
        hashes = ARC_HASH_ALGORITHMS
    else:
        hashes = HASH_ALGORITHMS
    for field in mandatory_fields:
        if field not in sig:
            raise dkim.ValidationError("missing %s=" % field)
    if b'a' in sig and not sig[b'a'] in hashes:
        raise dkim.ValidationError("unknown signature algorithm: %s" % sig[b'a'])

    if b'b' in sig:
        if re.match(br"[\s0-9A-Za-z+/]+[\s=]*$", sig[b'b']) is None:
            raise dkim.ValidationError("b= value is not valid base64 (%s)" % sig[b'b'])
        if len(re.sub(br"\s+", b"", sig[b'b'])) % 4 != 0:
            raise dkim.ValidationError("b= value is not valid base64 (%s)" % sig[b'b'])

    if b'bh' in sig:
        if re.match(br"[\s0-9A-Za-z+/]+[\s=]*$", sig[b'b']) is None:
            raise dkim.ValidationError("bh= value is not valid base64 (%s)" % sig[b'bh'])
        if len(re.sub(br"\s+", b"", sig[b'bh'])) % 4 != 0:
            raise dkim.ValidationError("bh= value is not valid base64 (%s)" % sig[b'bh'])

def select_headers(headers, include_headers):
    """Select message header fields to be signed/verified.

    >>> h = [('from','biz'),('foo','bar'),('from','baz'),('subject','boring')]
    >>> i = ['from','subject','to','from']
    >>> select_headers(h,i)
    [('from', 'baz'), ('subject', 'boring'), ('from', 'biz')]
    >>> h = [('From','biz'),('Foo','bar'),('Subject','Boring')]
    >>> i = ['from','subject','to','from']
    >>> select_headers(h,i)
    [('From', 'biz'), ('Subject', 'Boring')]
    """
    sign_headers = []
    lastindex = {}
    # 以 include_headers 中的元素 到 headers 中倒序查找（从有往左查找）
    for h in include_headers:
        assert h == h.lower()
        i = lastindex.get(h, len(headers))
        while i > 0:
            i -= 1
            if h == headers[i][0].lower():
                sign_headers.append(headers[i])
                break
        lastindex[h] = i
    return sign_headers

class MYDKIM:
    def __init__(self, file: str, message_text: bytes = None):
        self.file = file
        self.message_text = message_text
        self.message = None
        # self.headers = []
        # self.body = ''
        self.domain = None
        self.selector = 'default'
        self.signature_fields = {}
        self.signature_headers = []
        # public_key 是一个 dict，{'modulus' 200xxx, 'publicExponent': 65537}，
        # 示例：{'modulus': 20054049931062868895890884170436368122145070743595938421415808271536128118589158095389269883866014690926251520949836343482211446965168263353397278625494421205505467588876376305465260221818103647257858226961376710643349248303872103127777544119851941320649869060657585270523355729363214754986381410240666592048188131951162530964876952500210032559004364102337827202989395200573305906145708107347940692172630683838117810759589085094521858867092874903269345174914871903592244831151967447426692922405241398232069182007622735165026000699140578092635934951967194944536539675594791745699200646238889064236642593556016708235359, 'publicExponent': 65537}
        self.public_key: RSA.RsaKey

        self.sigheaders = None
        # self.dkim_signature: bytes = b''
        self.dkim_signature_tags: dict = {}
        self.dkim_dns_txt_dict: dict = {}
        self.include_headers: list = []
        self.k_tag = b''  # dkim DNS TXT 记录中指定的 k 值，即加密算法
        self.algorithm = b'rsa-sha256'
        self.sign_headers: list = []  # 示例：(b'DKIM-Signature', b' v=1; a=rsa-sha256; c=relaxed/relaxed;\r\n        d=gmail.com; s=20230601; t=1721280239; x=1721885039; darn=qq.com;\r\n        h=to:subject:message-id:date:from:mime-version:from:to:cc:subject\r\n         :date:message-id:reply-to;\r\n        bh=k6PZ3BBA0FIv7OCGbWMDNiMSvnIntoNPtciA688Nqwo=;\r\n        b=gzCd0JCJkdOYxGudoEBxop6h6PaYlu7VrJS+N3oBhd++SaxvbkGZoXLPRGSBqW3Ruk\r\n         OOOmijuHc0Ee7AlP/7AbYKwwYRzQfz3a13ghY+Lqx8NPVumUYNxJTgwgXseY5WYYTd7C\r\n         w9iUcMCuqI/rayCGD2qZ+XBFvQZ2+tJIPNwiZCL5+sc59YwXD0w1OL+e6nPEiNfH5Z/a\r\n         IfgZuuUv4GrMQKo6obQr/ZyXbRB1bcmNdhmFaximDJDhmMYh+8h4dDwH27Xx56Xhmlgi\r\n         N/xSC5yPJ+mhpIiK3u2bHZQC+Hy2bdgFecWIHn73BIvdRsBO8i+lGTpJsHKOUv2wzDBy\r\n         w8HQ==\r\n')


        self.prep()

    def get_message(self):
        if self.message_text:
            return self.message_text
        msg = BytesParser().parse(open(self.file, 'rb')).as_bytes()
        return msg

    def set_message(self, message:bytes):
        if message:
            self.headers, self.body = dkim.rfc822_parse(message)
    def get_dkim_signature(self):
        if not self.headers:
            return
        for i in self.headers:
            if b'DKIM-Signature'.lower() == bytes(i[0]).lower():
                # self.dkim_signature = i[1]
                self.sign_headers = (i[0], i[1])
                break

    def parse_tag_value(self):
        tags = {}
        tag_specs = self.sign_headers[1].strip().split(b';')
        # DKIM-Signature 值的最后含 ';' 是有效的，所以这里需要这部分去掉
        if not tag_specs[-1]:
            tag_specs.pop()
        for tag_spec in tag_specs:
            try:
                key,value = [x.strip() for x in tag_spec.split(b'=', 1)]
            except ValueError:
                raise InvalidTagSpec(tag_spec)
            if re.match(br'^[a-zA-A](\w)*', key) is None:
                raise InvalidTagSpec(tag_spec)
            if key in tags:
                raise DuplicateTag(key)
            tags[key] = value
        return tags

    def get_dkim_dns_txt(self):
        dns_name = f"{self.dkim_signature_tags[b's'].decode()}._domainkey.{self.dkim_signature_tags[b'd'].decode()}"
        self.dkim_dns_txt_dict = get_dkim_txt(dns_name)

        # generate public_key --start
        try:
            if self.dkim_dns_txt_dict[b'v'] != b'DKIM1':
                raise dkim.KeyFormatError("DKIM bad version")
        except KeyError as e:
            # Version not required in key record: RFC 6376 3.6.1
            pass

        # only needed for ed25519 signing/verification
        try:
            import nacl.signing
            import nacl.encoding
        except ImportError:
            pass
        try:
            if self.dkim_dns_txt_dict[b'k'] == b'ed25519':
                try:
                    pk = nacl.signing.VerifyKey(self.dkim_dns_txt_dict[b'p'], encoder=nacl.encoding.Base64Encoder)
                except NameError:
                    raise dkim.NaClNotFoundError('pynacl module required for ed25519 signing, see README.md')
                except nacl.exceptions.ValueError as e:
                    raise dkim.KeyFormatError("could not parse ed25519 public key (%s): %s" % (self.dkim_dns_txt_dict[b'p'], e))
                keysize = 256
                ktag = b'ed25519'
        except KeyError:
            self.dkim_dns_txt_dict[b'k'] = b'rsa'
        if self.dkim_dns_txt_dict[b'k'] == b'rsa':
            try:
                self.public_key = parse_public_key(base64.b64decode(self.dkim_dns_txt_dict[b'p']))
                self.keysize = dkim.bitsize(self.public_key['modulus'])
            except KeyError:
                raise dkim.KeyFormatError("incomplete RSA public key: %s" % self.dkim_dns_txt_dict[b'p'])
            except (TypeError, UnparsableKeyError) as e:
                raise dkim.KeyFormatError("could not parse RSA public key (%s): %s" % (self.dkim_dns_txt_dict[b'p'], e))
            self.k_tag = b'rsa'
        # generate public_key --end


    def do_process(self):
        self.include_headers = [x.lower() for x in re.split(br"\s*:\s*", self.dkim_signature_tags[b'h'])]  # \s*:\s* 表示 `:` 或 ` : ` 或 ` *: *`
        self.k_tag = (self.dkim_dns_txt_dict[b'k'])


    def verify_mail_expire(self):
        """ 验证是否过期

        @return:
        """
        # 签名时间
        if b't' in self.dkim_signature_tags:
            now = int(time.time())
            sign_time = int(self.dkim_signature_tags[b't'])

            slop = 3600 * 10  # 允许的过期溢出时间（如时间不准确的情况），10H

            if (now + slop) < sign_time:
                print('== 邮件过期时间验证未通过，你的时间与标准时间慢太多了. ==')
                raise dkim.ValidationError(f"t= value is in the future ({now}--{timestamp_format(now)}), the sinature time is ({sign_time}--{timestamp_format(sign_time)})")
        # 过期时间
        if b'x' in self.dkim_signature_tags:
            now = int(time.time())
            expire_time = int(self.dkim_signature_tags[b'x'])
            slop = 3600 * 10  # 允许的过期溢出时间（如时间不准确的情况），10H
            if now - slop > expire_time:
                print('== 已经过了邮件过期时间验证时间. ==')
                raise ValidationError(
                    "x= value is past (%s)" % expire_time)
            if sign_time and expire_time < sign_time:
                raise ValidationError(
                    "x= value is less than t= value (x=%s t=%s)" %
                    (expire_time, sign_time))

        print('== 邮件过期时间验证通过. ==')
    def verify_mail_body(self):
        bh_base64_encode = re.sub(br'\s+', b'', self.dkim_signature_tags[b'bh'])  # 删除所有的空格（空字符）
        bh = base64.b64decode(bh_base64_encode)

        hasher = HASH_ALGORITHMS[self.dkim_signature_tags[b'a']]()
        try:
            canon_policy = CanonicalizationPolicy.from_c_value(self.dkim_signature_tags.get(b'c', b'simple/simple'))
        except InvalidCanonicalizationPolicyError as e:
            raise dkim.MessageFormatError("invalid c= value: %s" % e.args[0])
        if b'bh' in self.dkim_signature_tags:
            body = canon_policy.canonicalize_body(self.body)
            if b'l' in self.dkim_signature_tags:
                body = body[:int(self.dkim_signature_tags[b'l'])]
            hasher.update(body)
            body_hash = hasher.digest()
            if body_hash != bh:
                print('== 邮件 body 验证未通过. ==')
                raise dkim.ValidationError(
                    "body hash mismatch (got %s, expected %s)" %
                    (base64.b64encode(body_hash), self.dkim_signature_tags[b'bh'])
                )
            else:
                print(f'body hash: {body_hash}')
                print(f'dkim_bh: {bh}')
                print()
                print(f'body hash base64 encode: {base64.b64encode(body_hash)}')
                print(f'dkim_bh base64 encode: {bh_base64_encode}')
                print('body of mail verify is OK')
            print('== 邮件 body 验证通过. ==')
    def verify_mail_headers(self):
        # address bug#644046 by including any additional From header
        # fields when verifying.  Since there should be only one From header,
        # this shouldn't break any legitimate messages.  This could be
        # generalized to check for extras of other singleton headers.
        # 示例：
        # [b'to', b'subject', b'message-id', b'date', b'from', b'mime-version', b'from', b'to', b'cc',
        #     b'subject', b'date', b'message-id', b'reply-to', b'from']
        if b'from' in self.include_headers:
            self.include_headers.append(b'from')

        try:
            canon_policy = CanonicalizationPolicy.from_c_value(self.dkim_signature_tags.get(b'c', b'simple/simple'))
        except InvalidCanonicalizationPolicyError as e:
            raise dkim.MessageFormatError("invalid c= value: %s" % e.args[0])

        dkim_headers_signature_base64_encode = re.sub(br"\s+", b"", self.dkim_signature_tags[b'b'])  # # 删除所有的空格（空字符）
        dkim_headers_signature = base64.b64decode(dkim_headers_signature_base64_encode)

        hasher = HASH_ALGORITHMS[self.dkim_signature_tags[b'a']]()
        headers = canon_policy.canonicalize_headers(self.headers)

        # Update hash for signed message header fields.
        sign_headers = select_headers(headers, self.include_headers)
        # The call to _remove() assumes that the signature b= only appears
        # once in the signature header
        cheaders = canon_policy.canonicalize_headers(
            [(self.sign_headers[0], dkim.RE_BTAG.sub(b'\\1', self.sign_headers[1]))]
        )
        need_to_sign_headers = sign_headers + [(x, y.rstrip()) for x, y in cheaders]
        # the dkim sig is hashed with no trailing crlf, even if the
        # canonicalization algorithm would add one.
        # print(need_to_sign_headers)
        # 签名的字段
        # [(b'to', b'hanxiao2100@qq.com\r\n'), (b'subject', b'Gmail to QQ mail\r\n'), (b'message-id', b'<CAHVr0BYim2JaDhEHAdWqLTMFXCXnvH=1nq-is7pE=oAZxMT2Bw@mail.gmail.com>\r\n'), (b'date', b'Thu, 18 Jul 2024 13:23:48 +0800\r\n'), (b'from', b'Xiao Han <hanxiao2100@gmail.com>\r\n'), (b'mime-version', b'1.0\r\n'), (b'dkim-signature', b'v=1; a=rsa-sha256; c=relaxed/relaxed; d=gmail.com; s=20230601; t=1721280239; x=1721885039; darn=qq.com; h=to:subject:message-id:date:from:mime-version:from:to:cc:subject :date:message-id:reply-to; bh=k6PZ3BBA0FIv7OCGbWMDNiMSvnIntoNPtciA688Nqwo=; b=')]
        for x, y in need_to_sign_headers:
            hasher.update(x)
            hasher.update(b":")
            hasher.update(y)

        dkim_signature_b: bytes = base64.b64decode(re.sub(br"\s+", b"", self.dkim_signature_tags[b'b']))
        if self.k_tag.lower() == b'rsa':
            # 1. 简单方法
            # res = RSASSA_PKCS1_v1_5_verify(hasher, dkim_signature_b, self.public_key)
            # if res:
            #     print('邮件 headers 验证通过.')
            #     return res

            # 2. 手动验证签名方法
            modlen = len(int2str(self.public_key['modulus']))
            digest_encoded = EMSA_PKCS1_v1_5_encode(hasher, modlen)  # EMSA_PKCS1_v1_5_encode 方法见 ./see_EMSA_PKCS1_v1_5_encode.py

            # 计算 signed_digest
            # signed_digest = rsa_encrypt(dkim_signature_b, self.public_key, modlen)
            # 或
            m = str2int(dkim_signature_b)
            signed_digest = int2str(pow(m, self.public_key['publicExponent'], self.public_key['modulus']), modlen)

            assert digest_encoded == signed_digest
            if digest_encoded == signed_digest:
                print(f'headers digest encoded is :{digest_encoded} \n')
                print(f'signed digest encode is :{bytes(signed_digest)} \n')
                print('== 邮件 headers 验证通过.==')
                return True
            else:
                print('== 邮件 headers 验证未通过.==')
                return False

            # # 此方法报错
            # rsa_key = RSA.importKey(base64.b64decode(self.dkim_dns_txt_dict[b'p']))
            # verifier = Signature_pkcs1_v1_5.new(rsa_key)
            # #
            # # is_verify = verifier.verify(hasher, signature=dkim_signature_b)
            # # print(is_verify)
            # 报错： '_hashlib.HASH' object has no attribute 'oid'

    def verify_mail(self, verify_expire=False):
        """ 验证邮件 DKIM

        @param verify_expire: bool
            是否需要验证时间
        @return:
        """
        try:
            if verify_expire:
                self.verify_mail_expire()
            self.verify_mail_body()
            self.verify_mail_headers()

            print('== Mail verify success. ==')
            return True
        except Exception as e:
            print(e)

    def prep(self):
        """ 预处理邮件

        """
        self.message = self.get_message()
        self.set_message(self.message)
        self.get_dkim_signature()
        self.dkim_signature_tags = self.parse_tag_value()
        self.get_dkim_dns_txt()
        self.do_process()

if __name__ == '__main__':
    # file = './Gmail_to_QQ_mail.eml'
    file = './Hotmail_to_QQ_mail.eml'
    obj = MYDKIM(file=file)
    # # 不验证过期时间
    # obj.verify_mail()
    # 需要验证过期时间
    obj.verify_mail(True)

