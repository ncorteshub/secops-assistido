import pytest
from secops_core.detectors.cloudtrail_rules import (
    CloudTrailRuleEngine,
    RuleViolation,
    Severity,
    register_rule,
)


@pytest.fixture
def engine() -> CloudTrailRuleEngine:
    return CloudTrailRuleEngine()


def test_clean_event_returns_empty_list(engine: CloudTrailRuleEngine):
    benign_event = {
        "eventSource": "ec2.amazonaws.com",
        "eventName": "DescribeInstances",
        "userIdentity": {"type": "IAMUser", "arn": "arn:aws:iam::123456789012:user/dev"},
        "sourceIPAddress": "10.0.0.15",
    }
    assert engine.evaluate(benign_event) == []


def test_rule_trail_tampering(engine: CloudTrailRuleEngine):
    event = {
        "eventSource": "cloudtrail.amazonaws.com",
        "eventName": "StopLogging",
        "userIdentity": {"type": "IAMUser"},
        "requestParameters": {"name": "corp-audit-trail"},
    }
    violations = engine.evaluate(event)
    assert len(violations) == 1
    assert violations[0].rule_code == "RULE_TRAIL_TAMPERING"
    assert violations[0].severity == Severity.CRITICAL
    assert "StopLogging" in violations[0].technical_reason


def test_rule_root_activity(engine: CloudTrailRuleEngine):
    event = {
        "eventSource": "s3.amazonaws.com",
        "eventName": "ListBuckets",
        "userIdentity": {"type": "Root"},
        "sourceIPAddress": "203.0.113.42",
    }
    violations = engine.evaluate(event)
    assert len(violations) == 1
    assert violations[0].rule_code == "RULE_ROOT_ACTIVITY"
    assert violations[0].severity == Severity.CRITICAL


def test_rule_iam_privilege_escalation(engine: CloudTrailRuleEngine):
    event = {
        "eventSource": "iam.amazonaws.com",
        "eventName": "AttachUserPolicy",
        "userIdentity": {"type": "IAMUser"},
        "requestParameters": {
            "userName": "estagiario",
            "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess",
        },
    }
    violations = engine.evaluate(event)
    assert len(violations) == 1
    assert violations[0].rule_code == "RULE_IAM_PRIVILEGE_ESCALATION"
    assert violations[0].severity == Severity.CRITICAL


def test_rule_sensitive_s3_public_access(engine: CloudTrailRuleEngine):
    event = {
        "eventSource": "s3.amazonaws.com",
        "eventName": "DeleteBucketPublicAccessBlock",
        "userIdentity": {"type": "AssumedRole"},
        "requestParameters": {"bucketName": "dados-clientes-prod"},
    }
    violations = engine.evaluate(event)
    assert len(violations) == 1
    assert violations[0].rule_code == "RULE_SENSITIVE_S3_PUBLIC_ACCESS"
    assert violations[0].severity == Severity.HIGH


def test_rule_brute_force_console(engine: CloudTrailRuleEngine):
    event = {
        "eventSource": "signin.amazonaws.com",
        "eventName": "ConsoleLogin",
        "userIdentity": {"type": "IAMUser", "arn": "arn:aws:iam::123456789012:user/admin"},
        "sourceIPAddress": "198.51.100.10",
        "responseElements": {"ConsoleLogin": "Failure"},
    }
    # Abaixo do limite: não dispara
    assert engine.evaluate(event, context={"failed_console_logins_window": 2}) == []

    # No limite: dispara
    violations = engine.evaluate(event, context={"failed_console_logins_window": 5})
    assert len(violations) == 1
    assert violations[0].rule_code == "RULE_BRUTE_FORCE_CONSOLE"
    assert violations[0].severity == Severity.HIGH


def test_rule_unauthorized_api_burst(engine: CloudTrailRuleEngine):
    event = {
        "eventSource": "secretsmanager.amazonaws.com",
        "eventName": "GetSecretValue",
        "errorCode": "AccessDenied",
        "userIdentity": {"type": "AssumedRole", "arn": "arn:aws:sts::123456789012:assumed-role/app/i-1"},
    }
    violations = engine.evaluate(event, context={"access_denied_count_window": 12})
    assert len(violations) == 1
    assert violations[0].rule_code == "RULE_UNAUTHORIZED_API_BURST"
    assert violations[0].severity == Severity.MEDIUM


def test_multiple_rules_triggered_simultaneously(engine: CloudTrailRuleEngine):
    """Conta Root desativando o CloudTrail deve disparar 2 regras ao mesmo tempo."""
    event = {
        "eventSource": "cloudtrail.amazonaws.com",
        "eventName": "DeleteTrail",
        "userIdentity": {"type": "Root"},
        "sourceIPAddress": "192.0.2.1",
        "requestParameters": {"name": "main-trail"},
    }
    violations = engine.evaluate(event)
    codes = {v.rule_code for v in violations}
    assert codes == {"RULE_ROOT_ACTIVITY", "RULE_TRAIL_TAMPERING"}


def test_extensibility_without_modifying_engine():
    """Garante que novas regras funcionam via decorator sem tocar no motor."""
    custom_rules = []

    def local_register(fn):
        custom_rules.append(fn)
        return fn

    @local_register
    def rule_kms_key_deletion(event, context=None):
        if event.get("eventName") == "ScheduleKeyDeletion":
            return RuleViolation(
                rule_code="RULE_KMS_KEY_DELETION",
                name="Agendamento de Exclusão de Chave KMS",
                severity=Severity.CRITICAL,
                technical_reason="Chave KMS agendada para exclusão.",
            )
        return None

    custom_engine = CloudTrailRuleEngine(rules=custom_rules)
    violations = custom_engine.evaluate({"eventName": "ScheduleKeyDeletion"})
    assert len(violations) == 1
    assert violations[0].rule_code == "RULE_KMS_KEY_DELETION"