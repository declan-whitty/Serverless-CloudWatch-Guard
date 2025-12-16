import json
import logging
import os

import boto3
from botocore.exceptions import BotoCoreError, ClientError

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

sns_client = boto3.client("sns")
MONITORED_ACTIONS = {"CreateUser", "AuthorizeSecurityGroupIngress"}


def lambda_handler(event, context):
    """
    Entrypoint for EventBridge-triggered CloudTrail events.
    Publishes an SNS alert when high-risk API calls are detected.
    """
    logger.info("Received event: %s", json.dumps(event))

    try:
        detail = event.get("detail", {}) or {}
        event_name = detail.get("eventName", "UnknownEvent")

        if event_name not in MONITORED_ACTIONS:
            logger.info("Ignoring event %s; not in monitored list.", event_name)
            return {"status": "ignored", "eventName": event_name}

        actor = extract_actor(detail)
        source_ip = extract_source_ip(detail)
        region = event.get("region") or detail.get("awsRegion") or "unknown"
        account_id = event.get("account") or detail.get("recipientAccountId") or "unknown"
        event_time = event.get("time") or detail.get("eventTime") or "unknown"
        event_id = event.get("id") or detail.get("eventID") or "unknown"

        sns_topic_arn = os.environ.get("SNS_TOPIC_ARN")
        if not sns_topic_arn:
            logger.error("SNS_TOPIC_ARN environment variable is not set.")
            return {"status": "error", "reason": "SNS_TOPIC_ARN not set"}

        message = build_alert_message(
            event_name=event_name,
            actor=actor,
            source_ip=source_ip,
            region=region,
            account_id=account_id,
            event_time=event_time,
            event_id=event_id,
            raw_request=detail.get("requestParameters"),
        )
        subject = "SECURITY ALERT: High Risk Action Detected"

        response = sns_client.publish(
            TopicArn=sns_topic_arn,
            Subject=subject,
            Message=message,
        )
        logger.info("Alert published. MessageId=%s", response.get("MessageId"))
        return {"status": "alert_published", "messageId": response.get("MessageId")}
    except (ClientError, BotoCoreError) as boto_err:
        logger.exception("Boto3 error while publishing alert: %s", boto_err)
        return {"status": "error", "reason": str(boto_err)}
    except Exception as exc:
        logger.exception("Unhandled error while processing security alert: %s", exc)
        return {"status": "error", "reason": str(exc)}


def extract_actor(detail):
    """Best-effort extraction of the IAM principal name."""
    identity = detail.get("userIdentity", {}) or {}
    if identity.get("userName"):
        return identity["userName"]
    if identity.get("arn"):
        return identity["arn"]
    if identity.get("principalId"):
        return identity["principalId"]
    return "UnknownUser"


def extract_source_ip(detail):
    """Best-effort extraction of the caller IP."""
    return detail.get("sourceIPAddress") or detail.get("requestParameters", {}).get("sourceIp") or "unknown"


def build_alert_message(
    event_name,
    actor,
    source_ip,
    region,
    account_id,
    event_time,
    event_id,
    raw_request=None,
):
    request_snippet = json.dumps(raw_request, default=str) if raw_request else "None provided"

    lines = [
        "High risk AWS action detected.",
        f"Action: {event_name}",
        f"Actor: {actor}",
        f"Source IP: {source_ip}",
        f"Region: {region}",
        f"AWS Account: {account_id}",
        f"Event Time: {event_time}",
        f"Event ID: {event_id}",
        f"Request Parameters: {request_snippet}",
        "Recommended actions: verify actor legitimacy, review recent CloudTrail activity, and consider temporary credential revocation if suspicious.",
    ]
    return "\n".join(lines)


# Dummy CloudTrail-style event for local testing (CreateUser).
TEST_EVENT_CREATE_USER = {
    "version": "0",
    "id": "11111111-2222-3333-4444-555555555555",
    "detail-type": "AWS API Call via CloudTrail",
    "source": "aws.iam",
    "account": "123456789012",
    "time": "2024-12-16T17:00:00Z",
    "region": "us-east-1",
    "resources": [],
    "detail": {
        "eventVersion": "1.08",
        "userIdentity": {
            "type": "IAMUser",
            "principalId": "AIDASAMPLEID",
            "arn": "arn:aws:iam::123456789012:user/AdminUser",
            "accountId": "123456789012",
            "userName": "AdminUser",
        },
        "eventTime": "2024-12-16T17:00:00Z",
        "eventSource": "iam.amazonaws.com",
        "eventName": "CreateUser",
        "awsRegion": "us-east-1",
        "sourceIPAddress": "203.0.113.10",
        "userAgent": "aws-internal/3",
        "requestParameters": {"userName": "new-analyst"},
        "responseElements": None,
        "eventID": "abcdef12-3456-7890-abcd-ef1234567890",
        "readOnly": False,
        "eventType": "AwsApiCall",
        "managementEvent": True,
    },
}


if __name__ == "__main__":
    print("Sample CreateUser test event payload:")
    print(json.dumps(TEST_EVENT_CREATE_USER, indent=2))

    if os.environ.get("SNS_TOPIC_ARN"):
        print("SNS_TOPIC_ARN detected, invoking lambda_handler for end-to-end test.")
        lambda_handler(TEST_EVENT_CREATE_USER, None)
    else:
        print("SNS_TOPIC_ARN not set; skipping SNS publish. Set it and rerun to test end-to-end.")
