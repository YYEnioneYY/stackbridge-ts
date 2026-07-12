from typing import Any

from rest_framework import status
from rest_framework.exceptions import APIException, ValidationError
from rest_framework.response import Response
from rest_framework.views import exception_handler


class ServiceAPIException(APIException):
    status_code = status.HTTP_400_BAD_REQUEST
    default_detail = "The request could not be completed."
    default_code = "request_error"


def api_exception_handler(exc: Exception, context: dict[str, Any]) -> Response:
    response = exception_handler(exc, context)
    if response is None:
        return Response(
            {
                "error": {
                    "code": "internal_error",
                    "message": "An internal server error occurred.",
                    "details": {},
                }
            },
            status=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )
    if isinstance(exc, ValidationError):
        code = "validation_error"
        message = "Request validation failed."
        details = response.data
    else:
        codes = exc.get_codes() if isinstance(exc, APIException) else "request_error"
        code = codes if isinstance(codes, str) else "request_error"
        detail = exc.detail if isinstance(exc, APIException) else response.data
        message = str(detail) if not isinstance(detail, (dict, list)) else "The request could not be completed."
        details = {} if not isinstance(detail, (dict, list)) else detail
    response.data = {"error": {"code": code, "message": message, "details": details}}
    return response
