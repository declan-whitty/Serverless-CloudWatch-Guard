
import copy
import os
import unittest
from unittest.mock import MagicMock, patch

from botocore.exceptions import ClientError

# Prevent the module from creating a real AWS client at import.
with patch("boto3.client") as mock_boto_client:
    import lambda_function as guard

guard.sns_client = MagicMock()

TEST_TOPIC = "arn:aws:sns:us-east-1:123456789012:test-alerts"


class TestCloudWatchGuard(unittest.TestCase):

    def setUp(self):
        self.event = copy.deepcopy(guard.TEST_EVENT_CREATE_USER)

        guard.sns_client.reset_mock()
        guard.sns_client.publish.side_effect = None
        guard.sns_client.publish.return_value = {
            "MessageId": "test-message-123"
        }

        env_patch = patch.dict(
            os.environ,
            {"SNS_TOPIC_ARN": TEST_TOPIC}
        )
        env_patch.start()
        self.addCleanup(env_patch.stop)

    def test_create_user_generates_alert(self):
        result = guard.lambda_handler(self.event, None)

        self.assertEqual(result["status"], "alert_published")
        self.assertEqual(result["messageId"], "test-message-123")

        guard.sns_client.publish.assert_called_once()

        kwargs = guard.sns_client.publish.call_args.kwargs
        self.assertEqual(kwargs["TopicArn"], TEST_TOPIC)

        message = kwargs["Message"]
        self.assertIn("CreateUser", message)
        self.assertIn("AdminUser", message)
        self.assertIn("203.0.113.10", message)
        self.assertIn("new-analyst", message)

    def test_unmonitored_event_is_ignored(self):
        self.event["detail"]["eventName"] = "DescribeInstances"

        result = guard.lambda_handler(self.event, None)

        self.assertEqual(result["status"], "ignored")
        guard.sns_client.publish.assert_not_called()

    def test_missing_topic_raises_error(self):
        os.environ.pop("SNS_TOPIC_ARN", None)

        with self.assertRaises(ValueError) as context:
            guard.lambda_handler(self.event, None)

        self.assertIn("SNS_TOPIC_ARN", str(context.exception))
        guard.sns_client.publish.assert_not_called()

    def test_sns_failure_raises_exception(self):
        guard.sns_client.publish.side_effect = ClientError(
            {
                "Error": {
                    "Code": "AccessDenied",
                    "Message": "SNS publish denied"
                }
            },
            "Publish"
        )

        with self.assertRaises(ClientError) as context:
            guard.lambda_handler(self.event, None)

        self.assertEqual(
            context.exception.response["Error"]["Code"],
            "AccessDenied"
        )
        guard.sns_client.publish.assert_called_once()


if __name__ == "__main__":
    unittest.main()
