import requests, time

def api_request(method, url, *, params=None, headers=None, data=None, max_attempts=2):
    for attempt in range(max_attempts):
        try:
            response = requests.request(
                method,
                url,
                params=params,
                headers=headers,
                data=data,
                timeout=5
            )

            # Successful response
            if 200 <= response.status_code < 300:
                try:
                    return response.json()
                except ValueError:
                    print(f"Invalid JSON response: {url}")
                    return None

            # Client-side errors / indicator not found.
            # Retrying these will normally not help.
            if response.status_code in (400, 401, 403, 404):
                print(
                    f"API request failed: "
                    f"HTTP {response.status_code} - {url}"
                )
                return None

            # Rate limited.
            # Respect Retry-After when provided.
            if response.status_code == 429:
                if attempt >= max_attempts - 1:
                    print(f"Rate limit retry exhausted: {url}")
                    return None

                retry_after = response.headers.get("Retry-After", "1")

                try:
                    wait_time = int(retry_after)
                except ValueError:
                    wait_time = 1

                print(
                    f"Rate limited: {url} "
                    f"(waiting {wait_time} seconds)"
                )

                time.sleep(wait_time)
                continue

            # Temporary server-side failures.
            if response.status_code in (500, 502, 503, 504):
                print(
                    f"Server error: HTTP {response.status_code} "
                    f"- {url} "
                    f"(attempt {attempt + 1}/{max_attempts})"
                )

                if attempt < max_attempts - 1:
                    time.sleep(1)

                continue

            # Anything else that we don't explicitly retry.
            print(
                f"Unexpected HTTP status: "
                f"{response.status_code} - {url}"
            )
            return None

        except requests.exceptions.Timeout:
            print(
                f"Timeout: {url} "
                f"(attempt {attempt + 1}/{max_attempts})"
            )

        except requests.exceptions.ConnectionError:
            print(
                f"Connection error: {url} "
                f"(attempt {attempt + 1}/{max_attempts})"
            )

        except requests.exceptions.RequestException as exc:
            print(f"Request error: {url} - {exc}")
            return None

        except Exception as exc:
            print(f"Unexpected API error: {url} - {exc}")
            return None

        # Retry timeout / connection failures.
        if attempt < max_attempts - 1:
            time.sleep(1)

    print(f"All retry attempts failed: {url}")
    return None