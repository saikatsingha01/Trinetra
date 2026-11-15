import os, time, requests
from dotenv import load_dotenv

load_dotenv(os.path.join(os.path.dirname(__file__),".env"))

OLLAMA_ENGINE_URL = os.getenv("OLLAMA_ENGINE_URL","").rstrip("/")
LOGIC_ENGINE_URL = os.getenv("LOGIC_ENGINE_URL","").rstrip("/")


def post_to_ollama(email_id, parsed_email, security_analysis, threat_analysis, max_attempts=2):
    if not OLLAMA_ENGINE_URL:
        print("OLLAMA_ENGINE_URL not configured")
        return None

    for attempt in range(max_attempts):
        try:
            response = requests.post(
                f"{OLLAMA_ENGINE_URL}/receive-backend",
                json={
                    "email_id": email_id,
                    "parsed_email": parsed_email,
                    "security_analysis": security_analysis,
                    "threat_analysis": threat_analysis
                },
                timeout=20
            )

            response.raise_for_status()

            return response.json()

        except requests.exceptions.Timeout:
            print(
                f"Ollama timeout for {email_id} "
                f"(attempt {attempt + 1}/{max_attempts})"
            )

        except requests.exceptions.ConnectionError:
            print(
                f"Ollama connection error for {email_id} "
                f"(attempt {attempt + 1}/{max_attempts})"
            )

        except requests.exceptions.RequestException as exc:
            print(
                f"Ollama request failed for {email_id}: {exc}"
            )

        if attempt < max_attempts - 1:
            time.sleep(1)

    print(
        f"Ollama delivery failed after "
        f"{max_attempts} attempts for {email_id}"
    )

    return None


def post_to_logic(email_id, security_analysis, threat_analysis, max_attempts=2):
    if not LOGIC_ENGINE_URL:
        print("LOGIC_ENGINE_URL not configured")
        return None

    for attempt in range(max_attempts):
        try:
            response = requests.post(
                f"{LOGIC_ENGINE_URL}/receive-analysis",
                json={
                    "email_id": email_id,
                    "security_analysis": security_analysis,
                    "threat_analysis": threat_analysis
                },
                timeout=20
            )

            response.raise_for_status()

            return response.json()

        except requests.exceptions.Timeout:
            print(
                f"Logic timeout for {email_id} "
                f"(attempt {attempt + 1}/{max_attempts})"
            )

        except requests.exceptions.ConnectionError:
            print(
                f"Logic connection error for {email_id} "
                f"(attempt {attempt + 1}/{max_attempts})"
            )

        except requests.exceptions.RequestException as exc:
            print(
                f"Logic request failed for {email_id}: {exc}"
            )

        if attempt < max_attempts - 1:
            time.sleep(1)

    print(
        f"Logic delivery failed after "
        f"{max_attempts} attempts for {email_id}"
    )

    return None