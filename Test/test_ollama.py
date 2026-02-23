import requests

OLLAMA_IP = "172.17.63.4"  
PORT = "11434"
MODEL = "gpt-oss:20b"  

def test_chat():
    url = f"http://{OLLAMA_IP}:{PORT}/api/chat"
    print(f"📡 Sending POST request to: {url} ...")

    payload = {
        "model": MODEL,
        "messages": [
            {
                "role": "user",
                "content": "What is CO2?"
            }
        ],
        "stream": False 
    }

    try:
        response = requests.post(url, json=payload, timeout=50)

        if response.status_code == 200:
            print("\n SUCCESS: Response received!")
            response_data = response.json()
            print(f" AI Reply: {response_data['message']['content']}")
        else:
            print(f"\n Error: {response.status_code}")
            print(response.text)

    except Exception as e:
        print(f"\n Request Failed: {e}")

if __name__ == "__main__":
    test_chat()