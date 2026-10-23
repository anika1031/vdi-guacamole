import json, os, time, hmac, hashlib, base64
import urllib.request, urllib.parse, urllib.error
import boto3

ec2 = boto3.client('ec2')
GUAC = os.environ['GUAC_BASE']
SECRET = os.environ['TOKEN_SECRET'].encode()
LIVE = ['pending', 'running', 'stopping', 'stopped']

def b64(raw):
    return base64.urlsafe_b64encode(raw).decode().rstrip('=')

def unb64(text):
    return base64.urlsafe_b64decode(text + '=' * (-len(text) % 4))

def sign(body):
    return b64(hmac.new(SECRET, body.encode(), hashlib.sha256).digest())

def make_token(user, admin):
    data = {'u': user, 'a': admin, 'exp': int(time.time()) + 8 * 3600}
    body = b64(json.dumps(data).encode())
    return body + '.' + sign(body)

def read_token(event):
    header = (event.get('headers') or {}).get('authorization', '')
    if not header.startswith('Bearer '):
        return None
    try:
        body, sig = header[7:].split('.')
        if not hmac.compare_digest(sig, sign(body)):
            return None
        data = json.loads(unb64(body))
        return data if data['exp'] > time.time() else None
    except Exception:
        return None

def guac_login(user, pw):
    # Returns None if the login is wrong, otherwise True/False for admin
    form = urllib.parse.urlencode({'username': user, 'password': pw}).encode()
    try:
        r = urllib.request.urlopen(urllib.request.Request(GUAC + '/api/tokens', data=form), timeout=10)
    except urllib.error.HTTPError as e:
        if e.code in (400, 401, 403):
            return None
        raise
    t = json.loads(r.read())
    token, ds = t['authToken'], t['dataSource']
    admin = False
    try:
        url = GUAC + '/api/session/data/' + ds + '/users/' + urllib.parse.quote(user) + '/permissions?token=' + token
        perms = json.loads(urllib.request.urlopen(url, timeout=10).read())
        admin = 'ADMINISTER' in perms.get('systemPermissions', [])
    except Exception:
        pass
    try:
        urllib.request.urlopen(urllib.request.Request(GUAC + '/api/tokens/' + token, method='DELETE'), timeout=5)
    except Exception:
        pass
    return admin

def find_desktop(user):
    r = ec2.describe_instances(Filters=[
        {'Name': 'tag:VdiUser', 'Values': [user]},
        {'Name': 'instance-state-name', 'Values': LIVE}])
    items = [i for x in r['Reservations'] for i in x['Instances']]
    return items[0] if items else None

def all_desktops():
    r = ec2.describe_instances(Filters=[
        {'Name': 'tag:Project', 'Values': ['vdi-workshop']},
        {'Name': 'instance-state-name', 'Values': LIVE}])
    out = []
    for x in r['Reservations']:
        for i in x['Instances']:
            tags = {t['Key']: t['Value'] for t in i.get('Tags', [])}
            out.append({'id': i['InstanceId'], 'user': tags.get('VdiUser', '-'),
                        'state': i['State']['Name'], 'type': i['InstanceType']})
    return sorted(out, key=lambda d: d['user'])

def resp(code, obj):
    return {'statusCode': code, 'headers': {'Content-Type': 'application/json'}, 'body': json.dumps(obj)}

def lambda_handler(event, context):
    method = event['requestContext']['http']['method']
    path = event['rawPath']
    if method == 'OPTIONS':
        return {'statusCode': 204}
    try:
        body = json.loads(event.get('body') or '{}')
    except ValueError:
        return resp(400, {'error': 'Bad request'})

    if path == '/login' and method == 'POST':
        user = str(body.get('username', '')).strip()[:64]
        pw = str(body.get('password', ''))[:200]
        if not user or not pw:
            return resp(400, {'error': 'Enter your username and password'})
        try:
            admin = guac_login(user, pw)
        except Exception:
            return resp(502, {'error': 'Cannot reach the login service. Try again shortly.'})
        if admin is None:
            return resp(401, {'error': 'Invalid username or password'})
        return resp(200, {'token': make_token(user, admin), 'username': user, 'admin': admin})

    tok = read_token(event)
    if not tok:
        return resp(401, {'error': 'Please log in again'})

    try:
        if path == '/status' and method == 'GET':
            inst = find_desktop(tok['u'])
            if not inst:
                return resp(404, {'error': 'No desktop is assigned to you yet'})
            return resp(200, {'state': inst['State']['Name']})

        if path == '/start' and method == 'POST':
            inst = find_desktop(tok['u'])
            if not inst:
                return resp(404, {'error': 'No desktop is assigned to you yet'})
            if inst['State']['Name'] == 'stopped':
                ec2.start_instances(InstanceIds=[inst['InstanceId']])
            return resp(200, {'state': 'pending'})

        if path.startswith('/admin'):
            if not tok['a']:
                return resp(403, {'error': 'Administrators only'})
            desks = all_desktops()
            if path == '/admin/instances' and method == 'GET':
                return resp(200, {'instances': desks})
            if path == '/admin/start-all' and method == 'POST':
                ids = [d['id'] for d in desks if d['state'] == 'stopped']
                if ids:
                    ec2.start_instances(InstanceIds=ids)
                return resp(200, {'message': 'Starting %d desktops' % len(ids)})
            if path == '/admin/stop-all' and method == 'POST':
                ids = [d['id'] for d in desks if d['state'] == 'running']
                if ids:
                    ec2.stop_instances(InstanceIds=ids)
                return resp(200, {'message': 'Shutting down %d desktops' % len(ids)})
            # STAGE 3 BLOCK GOES HERE (Part 8)
    except Exception as e:
        print('error', type(e).__name__, str(e))
        return resp(500, {'error': 'Something went wrong. Please try again.'})
    return resp(404, {'error': 'Not found'})
