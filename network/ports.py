from enum import Enum


class ExtendedEnum(Enum):

    @classmethod
    def list(cls):
        return list(map(lambda c: c.value, cls))


class CommonPorts(ExtendedEnum):
    FTP = 21
    SSH = 22
    TELNET: 23
    SMTP = 25
    DNS = 53
    HTTP = 80
    POP3 = 110
    RPCBIND = 111
    MSRPC = 135
    NETBIOS_SN = 139
    IMAP = 143
    HTTPS = 443
    MICROSOFT_DS = 445
    IMAPS = 993
    POP3s = 995
    PPTP = 1723
    MYSQL = 3306
    MS_WBT_SERVER = 3389
    VNC = 5900
    HTTP_PROXY = 8080

