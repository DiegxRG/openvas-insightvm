import socket
import time
import xml.etree.ElementTree as ET
from xml.sax.saxutils import escape, quoteattr


class OpenVASRequestError(RuntimeError):
    def __init__(self, message, retryable=False):
        super().__init__(message)
        self.retryable = retryable


def parse_xml(data):
    # Reject declarations that could expand entities or reference external content.
    if b'<!DOCTYPE' in data.upper() or b'<!ENTITY' in data.upper():
        raise OpenVASRequestError('Declaraciones XML no admitidas')
    try:
        root = ET.fromstring(data)
    except ET.ParseError as exc:
        raise OpenVASRequestError('Respuesta GMP con XML inválido') from exc
    for node in root.iter():
        node.tag = node.tag.rsplit('}', 1)[-1]
    return root


class OpenVASClient:
    enforce_remote_filter = True

    def __init__(self, settings):
        self.settings = settings
        self.sock = None
        self.last_request_stats = {}

    def __enter__(self):
        try:
            self.sock = socket.create_connection((self.settings.gvm_host, self.settings.gvm_port), self.settings.gvm_timeout)
            self.request('<get_version/>')
            self.request('<authenticate><credentials><username>' + escape(self.settings.gvm_user) +
                         '</username><password>' + escape(self.settings.gvm_password) +
                         '</password></credentials></authenticate>')
            return self
        except OSError as exc:
            self.__exit__(None, None, None)
            endpoint = f'{self.settings.gvm_host}:{self.settings.gvm_port}'
            raise OpenVASRequestError(
                f'No se pudo conectar a GMP ({endpoint}): {type(exc).__name__}: {exc}',
                retryable=not isinstance(exc, PermissionError),
            ) from exc
        except Exception:
            self.__exit__(None, None, None)
            raise

    def __exit__(self, *args):
        if self.sock is not None:
            self.sock.close()
            self.sock = None

    def request(self, command):
        data = bytearray()
        parser = ET.XMLPullParser(events=('start', 'end'))
        depth = 0
        complete = False
        started = time.monotonic()
        deadline = started + self.settings.gvm_request_timeout
        declaration_tail = b''
        root = None
        try:
            self.sock.settimeout(min(self.settings.gvm_timeout, self.settings.gvm_request_timeout))
            self.sock.sendall(command.encode('utf-8'))
            while not complete:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise OpenVASRequestError(f'Se alcanzo GVM_REQUEST_TIMEOUT={self.settings.gvm_request_timeout}s', retryable=True)
                self.sock.settimeout(min(self.settings.gvm_timeout, remaining))
                chunk = self.sock.recv(65536)
                if not chunk:
                    raise OpenVASRequestError('GMP cerró una respuesta incompleta', retryable=True)
                data.extend(chunk)
                if len(data) > self.settings.report_max_kb * 1024:
                    raise OpenVASRequestError(
                        f'Respuesta GMP de al menos {len(data)} bytes supera '
                        f'OPENVAS_REPORT_MAX_KB={self.settings.report_max_kb}'
                    )
                declaration_scan = (declaration_tail + chunk).upper()
                if b'<!DOCTYPE' in declaration_scan or b'<!ENTITY' in declaration_scan:
                    raise OpenVASRequestError('Declaraciones XML no admitidas')
                declaration_tail = (declaration_tail + chunk)[-10:]
                parser.feed(chunk)
                # Python 3.13 defers Expat reparsing of fragmented tokens.
                # Flush so a self-closing reply is recognized without another recv.
                if hasattr(parser, 'flush'):
                    parser.flush()
                for event, element in parser.read_events():
                    if event == 'start' and depth == 0:
                        root = element
                    depth += 1 if event == 'start' else -1
                    if event == 'end' and depth == 0:
                        complete = True
            parser.close()
        except OSError as exc:
            raise OpenVASRequestError(
                f'Error de comunicacion GMP: {type(exc).__name__}: {exc}',
                retryable=not isinstance(exc, PermissionError),
            ) from exc
        except ET.ParseError as exc:
            raise OpenVASRequestError('Respuesta GMP con XML inválido') from exc
        # Reuse the incrementally parsed tree instead of parsing the full XML again.
        for node in root.iter():
            node.tag = node.tag.rsplit('}', 1)[-1]
        self.last_request_stats = {'response_bytes': len(data), 'duration_seconds': round(time.monotonic() - started, 6)}
        if root.get('status') != '200':
            # Do not include response bodies or authentication commands in logs.
            raise OpenVASRequestError('GMP rechazó la solicitud: status=' + str(root.get('status')))
        return root, bytes(data).decode('utf-8')

    def get_tasks(self, first, rows):
        return self.request(f'<get_tasks details="1" filter="first={first} rows={rows} sort=uuid"/>')

    def get_report(self, report_id, first, rows):
        # Numeric filters avoid version-specific names for critical severity.
        # GMP scores have one decimal; >6.9 includes 7.0 through 10.0.
        allowed = set(self.settings.severities)
        if allowed == {'critical'}:
            severity_filter = 'severity>8.9 severity<10.1'
        elif allowed == {'high'}:
            severity_filter = 'severity>6.9 severity<9.0'
        elif allowed == {'critical', 'high'}:
            severity_filter = 'severity>6.9 severity<10.1'
        else:
            raise ValueError('Solo se admiten severidades high y critical')
        filter_text = f'first={first} rows={rows} sort=uuid {severity_filter} apply_overrides=1 notes=0 overrides=0'
        response = self.request(f'<get_reports report_id={quoteattr(report_id)} details="1" '
                                f'lean="{int(self.settings.gvm_lean_report)}" ignore_pagination="0" '
                                f'filter={quoteattr(filter_text)}/>')
        self.last_request_stats['result_filter'] = filter_text
        return response
