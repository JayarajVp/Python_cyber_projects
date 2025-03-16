import re
from collections import Counter

def createlog(file_path):
    log_pat = re.compile(
        r'Timestamp:\s(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\n'
        r'Source IP:\s(?P<ip>\d+\.\d+\.\d+\.\d+)\n'
        r'Destination IP:\s(?P<dest_ip>\d+\.\d+\.\d+\.\d+)\n'
        r'Protocol:\s(?P<protocol>\w+)\n'
        r'Source Port:\s(?P<src_port>\d+|N/A)\n'
        r'Destination Port:\s(?P<dest_port>\d+|N/A)\n'
        r'Action:\s(?P<action>Blocked|Allowed)\n'
        r'Reason:\s(?P<reason>.+)'
    )
    
    log_entries = []
    with open(file_path, 'r') as file:
        log_text = file.read()
        matches = log_pat.finditer(log_text)
        for match in matches:
            log_entries.append(match.groupdict())
    
    return log_entries

def analysis_res(log_entries):
    blocked_count = sum(1 for entry in log_entries if entry['action'] == 'Blocked')
    allowed_count = sum(1 for entry in log_entries if entry['action'] == 'Allowed')

    ip_counter = Counter(entry['ip'] for entry in log_entries)
    common_ips = ip_counter.most_common(5)

    blocked_ips = Counter(entry['ip'] for entry in log_entries if entry['action'] == 'Blocked')
    common_blocked_ips = blocked_ips.most_common(5)

    return {
        'total_entries': len(log_entries),
        'blocked_entries': blocked_count,
        'allowed_entries': allowed_count,
        'most_common_ips': common_ips,
        'most_blocked_ips': common_blocked_ips
    }

def main():
    file_path = 'firelog.log'  
    logs = createlog(file_path)
    analysis = analysis_res(logs)

    print("Results of Analysis:")
    print(f"Total Log Entries: {analysis['total_entries']}")
    print(f"Blocked Requests: {analysis['blocked_entries']}")
    print(f"Allowed Requests: {analysis['allowed_entries']}")
    
    print("Most Common IPs:")
    for ip, count in analysis['most_common_ips']:
        print(f"{ip}: {count} times")

    print("Frequently Blocked IPs:")
    for ip, count in analysis['most_blocked_ips']:
        print(f"{ip}: {count} times")

if __name__ == "__main__":
    main()
