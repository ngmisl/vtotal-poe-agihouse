from __future__ import annotations

from typing import AsyncIterable
import aiohttp
import fastapi_poe as fp
from modal import App, Image, Secret, asgi_app, exit
import os
import base64

# Define the Modal app
app = App(
    name="virustotal-url-checker",
    secrets=[Secret.from_name("VTOTAL")]
)

SYSTEM_PROMPT = """
You are a bot that checks the safety of URLs using VirusTotal. For each response, generate a cute summary in HTML/CSS/JS in one file format.
Your ENTIRE response must be in this HTML format, with no additional text before or after.
"""

def get_url_id(url: str) -> str:
    """Generate the URL identifier using base64 encoding."""
    return base64.urlsafe_b64encode(url.encode()).decode().strip("=")

async def check_url_safety(url: str) -> dict:
    """Check the safety of a URL using VirusTotal and retrieve detailed URL information."""
    VIRUSTOTAL_API_KEY = os.environ["VTOTAL"]

    # Get the URL identifier
    url_id = get_url_id(url)

    # Fetch details on the URL
    url_info_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    headers = {
        "accept": "application/json",
        "x-apikey": VIRUSTOTAL_API_KEY
    }

    async with aiohttp.ClientSession() as session:
        async with session.get(url_info_url, headers=headers) as response:
            if response.status == 200:
                response_json = await response.json()
                url_data = response_json.get("data", {}).get("attributes", {})

                # Extract relevant information from the URL object
                return {
                    "categories": url_data.get("categories", {}),
                    "first_submission_date": url_data.get("first_submission_date"),
                    "last_analysis_date": url_data.get("last_analysis_date"),
                    "last_analysis_results": url_data.get("last_analysis_results", {}),
                    "last_analysis_stats": url_data.get("last_analysis_stats", {}),
                    "last_final_url": url_data.get("last_final_url"),
                    "reputation": url_data.get("reputation"),
                    "tags": url_data.get("tags", []),
                    "times_submitted": url_data.get("times_submitted"),
                    "title": url_data.get("title"),
                    "total_votes": url_data.get("total_votes", {}),
                    "trackers": url_data.get("trackers", {}),
                    "url": url_data.get("url"),
                }
            else:
                return {"error": f"Failed to fetch URL data from VirusTotal. Status code: {response.status}"}

class VirusTotalBot(fp.PoeBot):
    async def get_response(
        self, request: fp.QueryRequest
    ) -> AsyncIterable[fp.PartialResponse]:
        # Extract URL from user query
        user_message = request.query[-1].content
        url = user_message.split()[-1]  # Assumes URL is the last word in the message

        # Check URL safety
        safety_result = await check_url_safety(url)

        # Prepare a summary of the safety check
        html_prompt = f"""Create a cute HTML summary about the safety of the URL {url}.
        Use the following data from VirusTotal: {safety_result}
        Remember to follow the HTML structure specified in the system prompt."""

        # Create a new query with the system prompt and HTML prompt
        new_query = [
            fp.ProtocolMessage(role="system", content=SYSTEM_PROMPT),
            fp.ProtocolMessage(role="user", content=html_prompt)
        ]

        # Create a new request with the updated query
        new_request = fp.QueryRequest(
            version=request.version,
            type=request.type,
            message_id=request.message_id,
            query=new_query,
            access_key=request.access_key,
            user_id=request.user_id,
            conversation_id=request.conversation_id
        )

        # Get HTML response from Claude
        async for msg in fp.stream_request(
            new_request, "Claude-3.5-Sonnet", request.access_key
        ):
            yield msg

    async def get_settings(self, setting: fp.SettingsRequest) -> fp.SettingsResponse:
        return fp.SettingsResponse(server_bot_dependencies={"Claude-3.5-Sonnet": 1})

REQUIREMENTS = ["fastapi-poe==0.0.47", "aiohttp"]
image = Image.debian_slim().pip_install(*REQUIREMENTS)

@app.cls(image=image)
class Model:
    access_key: str | None = "kPz1qPvohtyds2UZV9ON10Oeo6GBtHS3"  # Your access key
    bot_name: str | None = "VirusTotal"

    @exit()
    def sync_settings(self):
        """Syncs bot settings on server shutdown."""
        if self.bot_name and self.access_key:
            try:
                fp.sync_bot_settings(self.bot_name, self.access_key)
            except Exception:
                print("\n*********** Warning ***********")
                print(
                    "Bot settings sync failed. For more information, see: https://creator.poe.com/docs/server-bots-functional-guides#updating-bot-settings"
                )
                print("\n*********** Warning ***********")

    @asgi_app()
    def fastapi_app(self):
        bot = VirusTotalBot()
        if not self.access_key:
            print(
                "Warning: Running without an access key. Please remember to set it before production."
            )
            app = fp.make_app(bot, allow_without_key=True)
        else:
            app = fp.make_app(bot, access_key=self.access_key)
        return app

@app.local_entrypoint()
def main():
    Model().run.remote()
