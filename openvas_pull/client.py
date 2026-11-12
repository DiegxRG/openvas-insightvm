import socket
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
    def __init__(self, settings):
        self.settings = settings
        self.sock = None

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
        try:
            self.sock.sendall(command.encode('utf-8'))
            while not complete:
                chunk = self.sock.recv(65536)
                if not chunk:
                    raise OpenVASRequestError('GMP cerró una respuesta incompleta', retryable=True)
                data.extend(chunk)
                if len(data) > self.settings.report_max_kb * 1024:
                    raise OpenVASRequestError(
                        f'Respuesta GMP de al menos {len(data)} bytes supera '
                        f'OPENVAS_REPORT_MAX_KB={self.settings.report_max_kb}'
                    )
                if b'<!DOCTYPE' in data.upper() or b'<!ENTITY' in data.upper():
                    raise OpenVASRequestError('Declaraciones XML no admitidas')
                parser.feed(chunk)
                # Python 3.13 defers Expat reparsing of fragmented tokens.
                # Flush so a self-closing reply is recognized without another recv.
                if hasattr(parser, 'flush'):
                    parser.flush()
                for event, _ in parser.read_events():
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
        root = parse_xml(bytes(data))
        if root.get('status') != '200':
            # Do not include response bodies or authentication commands in logs.
            raise OpenVASRequestError('GMP rechazó la solicitud: status=' + str(root.get('status')))
        return root, bytes(data).decode('utf-8')

    def get_tasks(self, first, rows):
        return self.request(f'<get_tasks details="1" filter="first={first} rows={rows} sort=uuid"/>')

    def get_report(self, report_id, first, rows):
        # Filter locally: Greenbone versions differ in their named severity levels.
        return self.request(f'<get_reports report_id={quoteattr(report_id)} details="1" '
                            f'filter="first={first} rows={rows} sort=uuid levels=hmlg overrides=1"/>')
