import urllib.request, json, sys
sys.stdout.reconfigure(encoding='utf-8')

BASE = 'http://localhost:8080'

def call(method, path, token, body=None):
    url = f'{BASE}{path}'
    data = json.dumps(body).encode() if body else None
    req = urllib.request.Request(url, data=data, method=method,
        headers={'Authorization': f'Bearer {token}', 'Content-Type': 'application/json'})
    try:
        r = urllib.request.urlopen(req)
        return r.status
    except urllib.error.HTTPError as e:
        return e.code

# Reset violations first
urllib.request.urlopen(urllib.request.Request(f'{BASE}/api/security/reset', method='POST'))

print('Simulating BOLA attacks (Arjun stealing Priya data)...')
s1 = call('GET', '/api/riders/rider_priya', 'token_arjun')
s2 = call('GET', '/api/riders/rider_priya/trips', 'token_arjun')
s3 = call('GET', '/api/riders/rider_priya/payment', 'token_arjun')
s4 = call('GET', '/api/riders/rider_priya/location', 'token_arjun')
print(f'  Profile={s1}, Trips={s2}, Payment={s3}, Location={s4}')

print('Simulating BOLA attacks (Priya stealing Kumar driver data)...')
s5 = call('GET', '/api/drivers/driver_kumar', 'token_priya')
s6 = call('GET', '/api/drivers/driver_kumar/earnings', 'token_priya')
s7 = call('GET', '/api/drivers/driver_kumar/documents', 'token_priya')
print(f'  Profile={s5}, Earnings={s6}, Documents={s7}')

print('Simulating BFLA attacks (Arjun accessing admin endpoints)...')
s8  = call('GET', '/api/admin/users', 'token_arjun')
s9  = call('GET', '/api/admin/reports/earnings', 'token_arjun')
s10 = call('GET', '/api/trips/trip_002', 'token_arjun')
print(f'  AdminUsers={s8}, EarningsReport={s9}, OtherTrip={s10}')

r = urllib.request.urlopen(f'{BASE}/api/security/violations')
data = json.loads(r.read())
summary = data['summary']

print()
print('=== VIOLATION SUMMARY ===')
print(f'  Total : {summary["total"]}')
print(f'  BOLA  : {summary["BOLA"]}')
print(f'  BFLA  : {summary["BFLA"]}')

print()
print('=== TOP ATTACKERS ===')
for name, count in data['top_attackers']:
    print(f'  {name}: {count} violations')

print()
print('=== TOP VICTIMS ===')
for name, count in data['top_victims']:
    print(f'  {name}: {count} violations')

print()
print('=== VIOLATION DETAILS ===')
for v in data['violations']:
    print(f'  [{v["severity"]:8}] {v["violation_type"]} | {v["attacker_name"]:<20} -> {v["victim_name"]:<20} | {v["resource_type"]}')

print()
print('Dashboard: http://localhost:8080/dashboard')
print('API Docs:  http://localhost:8080/docs')
