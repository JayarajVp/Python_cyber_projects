import shodan 
api_key="" #add you'r API key
def scan(domain):
    try:
        shodan_api= shodan.Shodan(api_key)
        result = shodan_api.host(domain)
        print("results are")
        print(f"IP: {result['ip_str']}")
        print(f"Open Ports: {result.get('ports', 'N/A')}")
        print("Vulnerabilities:")
        for item in result.get('vulns', []):
            print(f"- {item}")
    except shodan.APIError as e:
        print(f"Error: {e}")
scan("") #enter IP of target
