#!/usr/bin/env python3
import requests
import json
import sys

def test_api_call(prompt="analyze the security of scanme.nmap.com and provide a comprehensive report"):
    """Test the API call and capture full response"""
    url = "http://localhost:5001/v1/chat/completions"
    headers = {"Content-Type": "application/json"}
    data = {
        "model": "gpt-3.5-turbo",  # You may need to adjust this based on your API
        "messages": [
            {"role": "user", "content": prompt}
        ]
    }
    
    try:
        print(f"Sending request to: {url}")
        print(f"Payload: {json.dumps(data, indent=2)}")
        print("=" * 50)
        
        response = requests.post(url, headers=headers, json=data)
        
        print(f"Status Code: {response.status_code}")
        print(f"Headers: {dict(response.headers)}")
        print("=" * 50)
        
        if response.status_code == 200:
            try:
                # Try to parse as JSON
                json_response = response.json()
                print("JSON Response:")
                print(json.dumps(json_response, indent=2, ensure_ascii=False))
            except json.JSONDecodeError:
                print("Raw Response (not JSON):")
                print(response.text)
        else:
            print(f"Error Response: {response.text}")
            
        # Also save response to file
        with open("api_response.json", "w", encoding="utf-8") as f:
            if response.headers.get('content-type', '').startswith('application/json'):
                try:
                    json.dump(response.json(), f, indent=2, ensure_ascii=False)
                except:
                    f.write(response.text)
            else:
                f.write(response.text)
        print("\nResponse saved to api_response.json")
        
    except requests.exceptions.ConnectionError:
        print("Error: Could not connect to the API server. Is it running on localhost:5001?")
    except Exception as e:
        print(f"Error: {e}")

def test_all_scan_commands():
    commands = [
        "run nmap on scanme.nmap.com",
        "run masscan on scanme.nmap.com",
        "run rustscan on scanme.nmap.com",
        "run nikto on scanme.nmap.com",
        "run sslyze on scanme.nmap.com",
        "run gobuster on scanme.nmap.com"
    ]
    url = "http://localhost:5001/v1/chat/completions"
    headers = {"Content-Type": "application/json"}
    for cmd in commands:
        data = {
            "model": "mistral-nemo:latest",
            "messages": [
                {"role": "user", "content": cmd}
            ]
        }
        print(f"\n{'='*30}\nTesting: {cmd}\n{'='*30}")
        try:
            response = requests.post(url, headers=headers, json=data)
            print(f"Status Code: {response.status_code}")
            if response.status_code == 200:
                try:
                    json_response = response.json()
                    print("JSON Response:")
                    print(json.dumps(json_response, indent=2, ensure_ascii=False))
                except json.JSONDecodeError:
                    print("Raw Response (not JSON):")
                    print(response.text)
            else:
                print(f"Error Response: {response.text}")
            # Save each response to a separate file
            fname = f"api_response_{cmd.split()[1]}.json"
            with open(fname, "w", encoding="utf-8") as f:
                if response.headers.get('content-type', '').startswith('application/json'):
                    try:
                        json.dump(response.json(), f, indent=2, ensure_ascii=False)
                    except:
                        f.write(response.text)
                else:
                    f.write(response.text)
            print(f"Response saved to {fname}")
        except requests.exceptions.ConnectionError:
            print("Error: Could not connect to the API server. Is it running on localhost:5001?")
        except Exception as e:
            print(f"Error: {e}")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        prompt = " ".join(sys.argv[1:])
        test_api_call(prompt)
    else:
        test_all_scan_commands()
