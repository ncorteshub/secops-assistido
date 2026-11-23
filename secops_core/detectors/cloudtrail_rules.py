from enum import Enum
from typing import Any, Callable, Dict, List, Optional
from pydantic import BaseModel, Field


class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class RuleViolation(BaseModel):
    rule_code: str = Field(..., description="Identificador único da regra")
    name: str = Field(..., description="Nome amigável da regra")
    severity: Severity = Field(..., description="Nível de severidade")
    technical_reason: str = Field(..., description="Detalhe técnico do disparo")


RuleFunc = Callable[[Dict[str, Any], Optional[Dict[str, Any]]], Optional[RuleViolation]]

_RULE_REGISTRY: List[RuleFunc] = []


def register_rule(func: RuleFunc) -> RuleFunc:
    """Decorator para registrar regras de forma modular sem alterar o motor."""
    _RULE_REGISTRY.append(func)
    return func


def _get_field(event: Dict[str, Any], *keys: str, default: Any = None) -> Any:
    """Busca o primeiro campo existente entre variações snake_case (LGMS) e camelCase (CloudTrail)."""
    for key in keys:
        if key in event and event[key] is not None:
            return event[key]
    return default


# =====================================================================
# CATÁLOGO DE REGRAS DETERMINÍSTICAS (AWS CLOUDTRAIL)
# =====================================================================


@register_rule
def rule_trail_tampering(
    event: Dict[str, Any], context: Optional[Dict[str, Any]] = None
) -> Optional[RuleViolation]:
    """Detecta tentativas de desabilitar, deletar ou alterar trilhas de auditoria."""
    tampering_events = {
        "StopLogging",
        "DeleteTrail",
        "UpdateTrail",
        "PutEventSelectors",
    }
    event_name = _get_field(event, "event_name", "eventName")
    event_source = _get_field(event, "event_source", "eventSource", default="")
    if "cloudtrail" in event_source and event_name in tampering_events:
        params = _get_field(event, "request_parameters", "requestParameters", default={}) or {}
        trail_name = params.get("name", "desconhecido")
        return RuleViolation(
            rule_code="RULE_TRAIL_TAMPERING",
            name="Adulteração ou Desativação de CloudTrail",
            severity=Severity.CRITICAL,
            technical_reason=(
                f"Operação crítica '{event_name}' executada na trilha '{trail_name}', "
                "comprometendo a rastreabilidade de auditoria."
            ),
        )
    return None


@register_rule
def rule_root_activity(
    event: Dict[str, Any], context: Optional[Dict[str, Any]] = None
) -> Optional[RuleViolation]:
    """Detecta qualquer ação realizada diretamente pela conta Root da AWS."""
    user_identity = _get_field(event, "user_identity", "userIdentity", default={}) or {}
    identity_type = user_identity.get("type") or user_identity.get("user_type")
    user_arn = str(user_identity.get("arn") or "")
    if identity_type == "Root" or user_arn.endswith(":root"):
        event_name = _get_field(event, "event_name", "eventName", default="UnknownEvent")
        source_ip = _get_field(event, "source_ip", "sourceIPAddress", default="IP desconhecido")
        return RuleViolation(
            rule_code="RULE_ROOT_ACTIVITY",
            name="Atividade Detectada na Conta Root",
            severity=Severity.CRITICAL,
            technical_reason=(
                f"A conta Root executou '{event_name}' a partir de '{source_ip}'. "
                "O uso da conta Root viola o princípio do menor privilégio."
            ),
        )
    return None


@register_rule
def rule_iam_privilege_escalation(
    event: Dict[str, Any], context: Optional[Dict[str, Any]] = None
) -> Optional[RuleViolation]:
    """Detecta ações de IAM associadas à escalação de privilégios ou backdoors."""
    escalation_actions = {
        "AttachUserPolicy",
        "AttachRolePolicy",
        "PutUserPolicy",
        "PutRolePolicy",
        "CreateAccessKey",
        "CreateLoginProfile",
        "UpdateLoginProfile",
        "AddUserToGroup",
    }
    event_name = _get_field(event, "event_name", "eventName")
    event_source = _get_field(event, "event_source", "eventSource", default="")
    if "iam" in event_source and event_name in escalation_actions:
        params = _get_field(event, "request_parameters", "requestParameters", default={}) or {}
        policy_arn = params.get("policyArn", "")
        target = params.get("userName") or params.get("roleName") or "alvo não especificado"

        is_admin = "AdministratorAccess" in policy_arn or event_name in {
            "CreateAccessKey",
            "CreateLoginProfile",
        }
        severity = Severity.CRITICAL if is_admin else Severity.HIGH

        return RuleViolation(
            rule_code="RULE_IAM_PRIVILEGE_ESCALATION",
            name="Potencial Escalação de Privilégios no IAM",
            severity=severity,
            technical_reason=(
                f"Ação sensível '{event_name}' aplicada em '{target}'"
                f"{f' com política {policy_arn}' if policy_arn else ''}."
            ),
        )
    return None


@register_rule
def rule_sensitive_s3_public_access(
    event: Dict[str, Any], context: Optional[Dict[str, Any]] = None
) -> Optional[RuleViolation]:
    """Detecta exposição pública de buckets S3 ou remoção do Block Public Access."""
    s3_exposure_events = {
        "DeleteBucketPublicAccessBlock",
        "PutBucketPublicAccessBlock",
        "PutBucketPolicy",
        "PutBucketAcl",
    }
    event_name = _get_field(event, "event_name", "eventName")
    event_source = _get_field(event, "event_source", "eventSource", default="")
    if "s3" not in event_source or event_name not in s3_exposure_events:
        return None

    params = _get_field(event, "request_parameters", "requestParameters", default={}) or {}
    bucket = params.get("bucketName", "desconhecido")

    if event_name == "DeleteBucketPublicAccessBlock":
        return RuleViolation(
            rule_code="RULE_SENSITIVE_S3_PUBLIC_ACCESS",
            name="Exposição Pública de Bucket S3",
            severity=Severity.HIGH,
            technical_reason=f"Block Public Access removido do bucket '{bucket}'.",
        )

    if event_name == "PutBucketPublicAccessBlock":
        config = params.get("PublicAccessBlockConfiguration", {})
        if not all(
            [
                config.get("BlockPublicAcls", True),
                config.get("IgnorePublicAcls", True),
                config.get("BlockPublicPolicy", True),
                config.get("RestrictPublicBuckets", True),
            ]
        ):
            return RuleViolation(
                rule_code="RULE_SENSITIVE_S3_PUBLIC_ACCESS",
                name="Exposição Pública de Bucket S3",
                severity=Severity.HIGH,
                technical_reason=(
                    f"Configuração de bloqueio público enfraquecida no bucket '{bucket}': {config}."
                ),
            )

    if event_name == "PutBucketAcl":
        acl = params.get("x-amz-acl", "")
        if acl in {"public-read", "public-read-write", "authenticated-read"}:
            return RuleViolation(
                rule_code="RULE_SENSITIVE_S3_PUBLIC_ACCESS",
                name="Exposição Pública de Bucket S3",
                severity=Severity.CRITICAL,
                technical_reason=f"ACL pública ('{acl}') aplicada ao bucket '{bucket}'.",
            )

    if event_name == "PutBucketPolicy":
        policy_str = str(params.get("bucketPolicy", ""))
        if '"Principal":"*"' in policy_str.replace(" ", "") or '"Principal":{"AWS":"*"}' in policy_str.replace(" ", ""):
            return RuleViolation(
                rule_code="RULE_SENSITIVE_S3_PUBLIC_ACCESS",
                name="Exposição Pública de Bucket S3",
                severity=Severity.CRITICAL,
                technical_reason=f"Política com Principal '*' aplicada ao bucket '{bucket}'.",
            )

    return None


@register_rule
def rule_brute_force_console(
    event: Dict[str, Any], context: Optional[Dict[str, Any]] = None
) -> Optional[RuleViolation]:
    """Detecta falha de login no Console AWS com múltiplas tentativas em janela curta."""
    event_name = _get_field(event, "event_name", "eventName")
    if event_name != "ConsoleLogin":
        return None

    response_elements = _get_field(event, "response_elements", "responseElements", default={}) or {}
    status = _get_field(event, "status", default="")
    is_failure = response_elements.get("ConsoleLogin") == "Failure" or str(status).lower() in {"failure", "failed", "error"}
    if not is_failure:
        return None

    ctx = context or {}
    failed_attempts = ctx.get("failed_console_logins_window", 1)
    threshold = ctx.get("brute_force_threshold", 5)

    if failed_attempts >= threshold:
        source_ip = _get_field(event, "source_ip", "sourceIPAddress", default="IP desconhecido")
        user_identity = _get_field(event, "user_identity", "userIdentity", default={}) or {}
        user_arn = user_identity.get("arn", "usuário desconhecido")
        return RuleViolation(
            rule_code="RULE_BRUTE_FORCE_CONSOLE",
            name="Tentativa de Força Bruta no Console AWS",
            severity=Severity.HIGH,
            technical_reason=(
                f"{failed_attempts} falhas consecutivas de ConsoleLogin detectadas para "
                f"'{user_arn}' a partir do IP '{source_ip}' (limite: {threshold})."
            ),
        )
    return None


@register_rule
def rule_unauthorized_api_burst(
    event: Dict[str, Any], context: Optional[Dict[str, Any]] = None
) -> Optional[RuleViolation]:
    """Detecta rajada de chamadas negadas (AccessDenied / UnauthorizedOperation)."""
    error_code = _get_field(event, "error_code", "errorCode", default="")
    if error_code not in {"AccessDenied", "Client.UnauthorizedOperation", "UnauthorizedOperation"}:
        return None

    ctx = context or {}
    denied_count = ctx.get("access_denied_count_window", 1)
    threshold = ctx.get("unauthorized_burst_threshold", 10)

    if denied_count >= threshold:
        user_identity = _get_field(event, "user_identity", "userIdentity", default={}) or {}
        principal = user_identity.get("arn", "identidade desconhecida")
        event_name = _get_field(event, "event_name", "eventName", default="UnknownEvent")
        return RuleViolation(
            rule_code="RULE_UNAUTHORIZED_API_BURST",
            name="Rajada de Chamadas de API Não Autorizadas",
            severity=Severity.MEDIUM,
            technical_reason=(
                f"Identidade '{principal}' acumulou {denied_count} erros '{error_code}' "
                f"(último evento: '{event_name}'), indicando possível enumeração de permissões."
            ),
        )
    return None


# =====================================================================
# MOTOR PRINCIPAL DE AVALIAÇÃO
# =====================================================================


class CloudTrailRuleEngine:
    """Avalia eventos CloudTrail contra o catálogo de regras determinísticas."""

    def __init__(self, rules: Optional[List[RuleFunc]] = None) -> None:
        self._rules = rules if rules is not None else list(_RULE_REGISTRY)

    @property
    def registered_rules_count(self) -> int:
        return len(self._rules)

    def evaluate(
        self, event: Dict[str, Any], context: Optional[Dict[str, Any]] = None
    ) -> List[RuleViolation]:
        violations: List[RuleViolation] = []
        for rule in self._rules:
            violation = rule(event, context)
            if violation is not None:
                violations.append(violation)
        return violations