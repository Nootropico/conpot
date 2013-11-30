import json
import logging
import uuid
from datetime import datetime

from conpot.logging.sqlite_log import SQLiteLogger
from conpot.logging.hpfriends import HPFriendsLogger
from conpot.logging.syslog import SysLogger
from conpot.logging.stix_transform import StixTransformer

logger = logging.getLogger(__name__)


class LogWorker(object):
    def __init__(self, config, log_queue, public_ip):
        self.log_queue = log_queue
        self.sqlite_logger = None
        self.friends_feeder = None
        self.syslog_client = None
        self.public_ip = public_ip
        # this will be wrapped in some sort of transport mechanism before the final merge
        self.stix_transformer = None

        if config.getboolean('sqlite', 'enabled'):
            self.sqlite_logger = SQLiteLogger()

        if config.getboolean('hpfriends', 'enabled'):
            host = config.get('hpfriends', 'host')
            port = config.getint('hpfriends', 'port')
            ident = config.get('hpfriends', 'ident')
            secret = config.get('hpfriends', 'secret')
            channels = eval(config.get('hpfriends', 'channels'))
            try:
                self.friends_feeder = HPFriendsLogger(host, port, ident, secret, channels)
            except Exception as e:
                logger.exception(e.message)
                self.friends_feeder = None

        if config.getboolean('syslog', 'enabled'):
            host = config.get('syslog', 'host')
            port = config.getint('syslog', 'port')
            facility = config.get('syslog', 'facility')
            logdevice = config.get('syslog', 'device')
            logsocket = config.get('syslog', 'socket')
            self.syslog_client = SysLogger(host, port, facility, logdevice, logsocket)

        if config.getboolean('stix', 'enabled'):
            self.stix_transformer = StixTransformer();

        self.enabled = True

    def start(self):
        self.enabled = True
        while self.enabled:
            event = self.log_queue.get()
            assert 'data_type' in event
            assert 'timestamp' in event

            if self.public_ip:
                event['public_ip'] = self.public_ip

            if self.friends_feeder:
                self.friends_feeder.log(json.dumps(event, default=self.json_default))

            if self.sqlite_logger:
                self.sqlite_logger.log(event)

            if self.syslog_client:
                self.syslog_client.log(event)

            if self.stix_transformer:
                self.stix_transformer.transform(event)

    def stop(self):
        self.enabled = False

    def json_default(self, obj):
        if isinstance(obj, datetime):
            return obj.isoformat()
        elif isinstance(obj, uuid.UUID):
            return str(obj)
        else:
            return None