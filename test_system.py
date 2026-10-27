from app.core.subnet_calc import calculate_subnet, check_ip_in_subnet
from app.core.ip_engine import ip_threat_engine
from app.core.detection import detection_engine
from app.core.traffic_stream import traffic_manager

# 1. Test Subnet Calc & CIDR Membership
sub = calculate_subnet('192.168.1.1', 24)
assert sub['subnet_mask'] == '255.255.255.0'
assert sub['total_hosts'] == 256
assert sub['usable_hosts'] == 254
assert sub['ip_class'] == 'C'

mem_check = check_ip_in_subnet('192.168.1.50', '192.168.1.0/24')
assert mem_check['is_member'] is True
assert mem_check['host_index'] == 50
print('[OK] NetCalc Pro Subnet Calculation & Membership Passed')

# 2. Test IP Threat Assessment (Slide 6 Sample)
intel = ip_threat_engine.assess_ip('198.51.100.42')
assert intel['valid'] is True
assert intel['asn'] == 'AS13335'
assert intel['risk_score'] == 78
assert 'session_steps' in intel
assert len(intel['session_steps']) >= 5
print(f'[OK] IP Threat Assessment Passed: Score {intel["risk_score"]}/100, ASN {intel["asn"]}, Session Steps: {len(intel["session_steps"])}')

# 3. Test Brute Force Detection & Slide 9 Triage Flow
for _ in range(5):
    traffic_manager.generate_event(forced_scenario='brute_force')
alerts = detection_engine.get_alerts()
assert len(alerts) > 0

investigation = detection_engine.investigate_incident(alerts[0]['id'])
assert investigation is not None
assert 'key_triage_question' in investigation
assert 'remediation_steps' in investigation
print(f'[OK] Intrusion Detection & Triage Passed: Alert {alerts[0]["id"]}, Verdict: {investigation["triage_verdict"]}')

# 4. Test Log Normalization
with open('logs/sample_access.log', 'r') as f:
    sample_text = f.read()
parsed = traffic_manager.parse_raw_access_log(sample_text)
assert len(parsed) > 5
print(f'[OK] Log Normalization Passed: Ingested {len(parsed)} events from raw log file')

print('=== ALL FUNCTIONAL VERIFICATION TESTS PASSED SUCCESSFULLY! ===')
