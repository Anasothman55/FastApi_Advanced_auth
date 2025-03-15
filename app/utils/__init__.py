from typing import  Any


def response_result(success: bool, message: str, data: Any):
  return {
    "success": success,
    "message": message,
    "data": data,
  }



