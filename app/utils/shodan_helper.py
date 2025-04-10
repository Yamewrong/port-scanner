import requests

def search_shodan(api_key, query):
    url = f"https://api.shodan.io/shodan/host/search?key={api_key}&query={query}"
    try:
        response = requests.get(url)
        data = response.json()
        return data.get("matches", [])
    except Exception as e:
        return {"error": str(e)}
