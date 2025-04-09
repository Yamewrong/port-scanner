# external_helper.py
import re

def guess_service_from_banner(entry):
    """배너나 응답 메시지를 기반으로 서비스명을 추정하는 함수"""
    banner = (entry.get('banner') or '') + (entry.get('response') or '')
    banner = banner.lower()

    guesses = [
        ('tomcat', r'tomcat|apache.*coyote'),
        ('nginx', r'nginx'),
        ('apache', r'apache|httpd'),
        ('jenkins', r'jenkins'),
        ('gitlab', r'gitlab'),
        ('mysql', r'mysql'),
        ('postgresql', r'postgres|pgsql'),
        ('mongodb', r'mongodb'),
        ('redis', r'redis'),
        ('elasticsearch', r'elasticsearch'),
        ('ftp', r'ftp'),
        ('ssh', r'ssh'),
        ('smb', r'smb|netbios'),
        ('vnc', r'vnc'),
        ('ldap', r'ldap'),
        ('kibana', r'kibana'),
        ('zookeeper', r'zookeeper'),
    ]

    for service, pattern in guesses:
        if re.search(pattern, banner):
            return service

    return 'unknown'
