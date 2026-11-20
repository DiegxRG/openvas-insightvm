class AcceptedSnapshot:
    status_code = 200

    def __init__(self, payload):
        self.payload = payload

    def json(self):
        count = len(self.payload['alarms'])
        return {'success': True, 'data': {
            'snapshot_id': self.payload['snapshot_id'],
            'total_alarmas': count,
            'registros_exitosos': count,
        }}
