import requests

url="http://www.google.com"

while True:
    response = requests.get(url)# send a get requst
    if response.status_code == 200:
        print("Success")
    else:
        print("Failed to retrieve the URL. status code", status_code)
