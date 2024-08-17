# VirusTotal URL Checker Bot

This repository contains a Python-based bot that uses the [VirusTotal API](https://www.virustotal.com/) to analyze URLs and retrieve detailed safety information. The bot is designed to integrate with [Modal](https://modal.com/) and [FastAPI-Poe](https://github.com/poe-api/fastapi-poe) to provide a robust, serverless solution for URL safety checks.

Poe Bot: https://poe.com/VirusTotal

## Features

- **URL Safety Analysis:** The bot retrieves comprehensive safety information for a given URL, including categories, analysis results, and overall reputation.
- **Detailed Scan Results:** Get results from various URL scanning engines, including whether the URL is categorized as harmless, malicious, suspicious, etc.
- **Submission History:** View the first and last submission dates, as well as the number of times a URL has been submitted to VirusTotal.
- **Redirection and HTTP Response Details:** Retrieve information about URL redirections, HTTP response codes, and content hashes.
- **Community Feedback:** See the reputation score and voting results from the VirusTotal community.

## Getting Started

### Prerequisites

- **Python 3.8+**
- **VirusTotal API Key:** You need a VirusTotal API key to access the API endpoints.
- **Modal Account:** For deploying the bot in a serverless environment.
- **FastAPI-Poe:** For handling the bot's API requests.

### Installation

1. Clone this repository:

   ```bash
   git clone https://github.com/<your-username>/virustotal-url-checker-bot.git
   cd virustotal-url-checker-bot
   ```

2. Install the required Python packages:

   ```bash
   pip install -r requirements.txt
   ```

3. Set up your VirusTotal API key as a secret in Modal:

   ```bash
   modal secret create VTOTAL --value=your_virustotal_api_key
   ```

### Usage

1. **Local Testing:**

   You can run the bot locally using Modal's local entrypoint:

   ```bash
   modal serve
   ```

2. **Deploying to Production:**

   Deploy the bot to Modal's serverless environment:

   ```bash
   modal deploy
   ```

3. **Interacting with the Bot:**

   Once deployed, you can interact with the bot by making API calls to check the safety of URLs.

### Example

Here’s an example of how to use the bot to check a URL:

![image](https://github.com/user-attachments/assets/087d216a-af81-4748-b945-1a1797653364)


### Contributing

Contributions are welcome! Please submit a pull request or open an issue to discuss improvements or new features.

### License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for more details.

---

This description should give potential users and contributors a clear understanding of what the project does, how to use it, and how to contribute.
