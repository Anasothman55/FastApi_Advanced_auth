from rich import  print

import json
import httpx
from starlette.middleware.base import BaseHTTPMiddleware
from fastapi import  Response,Request


class RefreshTokenMiddleware(BaseHTTPMiddleware):
  async def dispatch(self,request: Request, call_next):
    response = await call_next(request)

    if response.status_code == 403:
      response_body = b"".join([chunk async for chunk in response.body_iterator])
      response_text = response_body.decode("utf-8")

      try:
        check: dict = json.loads(response_text)
      except json.JSONDecodeError:
        return response

      if check.get("detail") == "Signature has expired.":

        async with httpx.AsyncClient(follow_redirects=True) as client:
          refresh_response = await client.get(
            "http://127.0.0.1:8000/auth/refresh_token",  # Adjust if needed
            cookies=request.cookies
          )

          if refresh_response.status_code == 201:
            # Return the refreshed response with updated cookies
            print("refresh")
            return Response(
              content=refresh_response.content,
              status_code=refresh_response.status_code,
              headers=dict(refresh_response.headers),
              media_type=refresh_response.headers.get("content-type"),
            )

            #return Response(
            #  content=response_body,
            #  status_code=response.status_code,
            #  headers=dict(response.headers),
            #  media_type=response.media_type
            #)

    return response






