import json

import pytest

from hello_world import app


@pytest.fixture()
def schedule_event():
    """ Generates API GW Event"""

    return {
        "version": "0",
        "id": "53dc4d37-cffa-4f76-80c9-8b7d4a4d2eaa",
        "detail-type": "Scheduled Event",
        "source": "aws.events",
        "account": "123456789012",
        "time": "2015-10-08T16:53:06Z",
        "region": "us-east-1",
        "resources": [
            "arn:aws:events:us-east-1:123456789012:rule/my-scheduled-rule"
        ],
        "detail": {}
    }


def test_lambda_handler(schedule_event, mocker):

    ret = app.lambda_handler(schedule_event, "")
    data = json.loads(ret["body"])

    assert ret["statusCode"] == 200
    assert "message" in ret["body"]
    assert data["message"] == "Completed Successfully"
