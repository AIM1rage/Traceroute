import requests

ttl_value = 0
headers = {'ttl': str(ttl_value)}

response = requests.get('http://python.org', headers=headers)

if response.status_code == 200:
    print('Request successful')
    print('Response:', response.text)
else:
    print('Request failed with status code:', response.status_code)
