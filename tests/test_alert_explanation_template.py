import pytest
from jinja2.exceptions import UndefinedError

from secops_core.detectors.cloudtrail_rules import RuleViolation, Severity
from secops_core.explainer.renderer import (
    AlertExplanationContext,
    AlertExplanationRenderer,
    render_alert_explanation,
)
from secops_core.pipeline import DetectionResult


MANDATORY_SECTIONS = [
    "1) O que aconteceu (Resumo Simples)",
    "2) Por que foi considerado anômalo",
    "3) Risco Potencial",
    "4) Ação Recomendada",
]


def assert_mandatory_sections_and_no_unrendered_tokens(prompt: str) -> None:
    """Verifica que as 4 seções obrigatórias existem e nenhuma tag Jinja2 restou sem renderizar."""
    for section in MANDATORY_SECTIONS:
        assert section in prompt, f"Seção obrigatória ausente no prompt: {section}"

    assert "{{" not in prompt, "Tag Jinja2 '{{' não renderizada encontrada no prompt"
    assert "}}" not in prompt, "Tag Jinja2 '}}' não renderizada encontrada no prompt"
    assert "{%" not in prompt, "Tag Jinja2 '{%' não renderizada encontrada no prompt"
    assert "%}" not in prompt, "Tag Jinja2 '%}' não renderizada encontrada no prompt"

    # Anti-alucinação e diretiva de idioma pt-BR
    assert "ANTI-ALUCINAÇÃO" in prompt
    assert "português do Brasil" in prompt


class TestAlertExplanationTemplate:
    """Suíte de testes para a Task MAO-16 (Templates Jinja2 estruturados para SecOps LLMs)."""

    @pytest.fixture
    def renderer(self) -> AlertExplanationRenderer:
        return AlertExplanationRenderer()

    def test_scenario_1_statistical_only(self, renderer: AlertExplanationRenderer):
        """Cenário 1: Apenas anomalia estatística (zscore presente, demais ausentes/nulos)."""
        prompt = renderer.render(
            user="arn:aws:iam::123456789012:user/analyst",
            source_ip="198.51.100.24",
            event_name="GetObject",
            event_source="s3.amazonaws.com",
            timestamp="2026-11-24T14:30:00Z",
            severity="MEDIUM",
            zscore=4.82,
            iforest_score=None,
            cloudtrail_rules=None,
        )

        assert_mandatory_sections_and_no_unrendered_tokens(prompt)

        # Dados do log
        assert "arn:aws:iam::123456789012:user/analyst" in prompt
        assert "198.51.100.24" in prompt
        assert "GetObject" in prompt
        assert "s3.amazonaws.com" in prompt
        assert "2026-11-24T14:30:00Z" in prompt
        assert "Severidade: MEDIUM" in prompt

        # Métrica Z-Score presente
        assert "Desvio Estatístico (Z-Score): 4.82" in prompt

        # Outros detectores não devem poluir o prompt
        assert "Isolation Forest" not in prompt
        assert "Regras Determinísticas CloudTrail Violadas" not in prompt

    def test_scenario_2_ml_isolation_forest_only(self, renderer: AlertExplanationRenderer):
        """Cenário 2: Apenas anomalia de Machine Learning (iforest_score presente)."""
        context = AlertExplanationContext(
            user="arn:aws:iam::123456789012:role/DataPipelineRole",
            source_ip="203.0.113.88",
            event_name="BatchGetItem",
            event_source="dynamodb.amazonaws.com",
            timestamp="2026-11-24T03:15:00Z",
            severity="HIGH",
            zscore=None,
            iforest_score=-0.2854,
            cloudtrail_rules=None,
        )

        prompt = renderer.render(context)

        assert_mandatory_sections_and_no_unrendered_tokens(prompt)

        # Dados do log
        assert "arn:aws:iam::123456789012:role/DataPipelineRole" in prompt
        assert "203.0.113.88" in prompt
        assert "BatchGetItem" in prompt
        assert "dynamodb.amazonaws.com" in prompt
        assert "Severidade: HIGH" in prompt

        # Métrica ML presente
        assert "Score de Machine Learning (Isolation Forest): -0.2854" in prompt

        # Outros detectores ausentes
        assert "Z-Score" not in prompt
        assert "Regras Determinísticas CloudTrail Violadas" not in prompt

    def test_scenario_3_rule_only(self, renderer: AlertExplanationRenderer):
        """Cenário 3: Apenas regra determinística (cloudtrail_rules presente)."""
        rules = [
            RuleViolation(
                rule_code="RULE_ROOT_ACTIVITY",
                name="Uso da Conta Root AWS",
                severity=Severity.HIGH,
                technical_reason="Ação administrativa crítica executada diretamente com as credenciais root.",
            ),
            RuleViolation(
                rule_code="RULE_TRAIL_TAMPERING",
                name="Adulteração ou Desativação de CloudTrail",
                severity=Severity.CRITICAL,
                technical_reason="Tentativa de execução de StopLogging na trilha principal.",
            ),
        ]

        prompt = renderer.render(
            user="arn:aws:iam::123456789012:root",
            source_ip="192.0.2.1",
            event_name="StopLogging",
            event_source="cloudtrail.amazonaws.com",
            timestamp="2026-11-24T22:00:00Z",
            severity="CRITICAL",
            zscore=None,
            iforest_score=None,
            cloudtrail_rules=rules,
        )

        assert_mandatory_sections_and_no_unrendered_tokens(prompt)

        # Dados do log
        assert "arn:aws:iam::123456789012:root" in prompt
        assert "192.0.2.1" in prompt
        assert "StopLogging" in prompt
        assert "Severidade: CRITICAL" in prompt

        # Regras presentes
        assert "Regras Determinísticas CloudTrail Violadas" in prompt
        assert "[RULE_ROOT_ACTIVITY] Uso da Conta Root AWS" in prompt
        assert "[RULE_TRAIL_TAMPERING] Adulteração ou Desativação de CloudTrail" in prompt
        assert "Tentativa de execução de StopLogging na trilha principal." in prompt

        # Detectores estatístico e ML ausentes
        assert "Z-Score" not in prompt
        assert "Isolation Forest" not in prompt

    def test_scenario_4_hybrid_anomaly(self, renderer: AlertExplanationRenderer):
        """Cenário 4: Anomalia Híbrida (combinação simultânea de zscore, ML e regras)."""
        rules = [
            {
                "rule_code": "RULE_EXCESSIVE_FAILURES",
                "name": "Múltiplas Falhas de Autenticação",
                "severity": "HIGH",
                "technical_reason": "Mais de 10 tentativas com falha seguidas por sucesso.",
            }
        ]

        prompt = render_alert_explanation(
            user="arn:aws:iam::123456789012:user/compromised_dev",
            source_ip="185.220.101.5",
            event_name="ConsoleLogin",
            event_source="signin.amazonaws.com",
            timestamp="2026-11-24T23:45:00Z",
            severity="CRITICAL",
            zscore=5.12,
            iforest_score=-0.412,
            cloudtrail_rules=rules,
            technical_justification="Regras determinísticas violadas simultaneamente com desvio estatístico e anomalia multivariada de ML.",
        )

        assert_mandatory_sections_and_no_unrendered_tokens(prompt)

        # Valida que todos os detectores constam simultaneamente
        assert "Desvio Estatístico (Z-Score): 5.12" in prompt
        assert "Score de Machine Learning (Isolation Forest): -0.412" in prompt
        assert "Regras Determinísticas CloudTrail Violadas:" in prompt
        assert "[RULE_EXCESSIVE_FAILURES] Múltiplas Falhas de Autenticação" in prompt
        assert "Justificativa Técnica Consolidada" in prompt

    def test_compatibility_with_pipeline_detection_result(self, renderer: AlertExplanationRenderer):
        """Valida compatibilidade direta com a classe DetectionResult do secops_core.pipeline."""
        violation = RuleViolation(
            rule_code="RULE_UNAUTHORIZED_ACCESS",
            name="Acesso Não Autorizado",
            severity=Severity.HIGH,
            technical_reason="Chamada retornou erro AccessDenied.",
        )

        detection_result = DetectionResult(
            event_id="evt-999",
            timestamp="2026-11-24T18:00:00Z",
            event_source="s3.amazonaws.com",
            event_name="PutBucketPolicy",
            is_anomaly=True,
            severity=Severity.HIGH,
            triggered_detectors=["Z_SCORE", "CLOUDTRAIL_RULES"],
            rule_violations=[violation],
            zscore_anomaly=True,
            zscore_value=3.75,
            isolation_forest_anomaly=False,
            isolation_forest_score=0.15,
            technical_justification="Desvio estatístico univariado e violação de regra determinística.",
            raw_event={
                "event_id": "evt-999",
                "user_identity": {"arn": "arn:aws:iam::123456789012:user/sec_tester"},
                "source_ip": "10.0.1.50",
            },
        )

        prompt = renderer.render(detection_result)

        assert_mandatory_sections_and_no_unrendered_tokens(prompt)
        assert "arn:aws:iam::123456789012:user/sec_tester" in prompt
        assert "10.0.1.50" in prompt
        assert "PutBucketPolicy" in prompt
        assert "s3.amazonaws.com" in prompt
        assert "Severidade: HIGH" in prompt
        assert "Desvio Estatístico (Z-Score): 3.75" in prompt
        assert "[RULE_UNAUTHORIZED_ACCESS] Acesso Não Autorizado" in prompt
        # Isolation Forest não foi anômalo (isolation_forest_anomaly=False), então não deve aparecer como evidência
        assert "Isolation Forest" not in prompt

    def test_strict_undefined_raises_on_unknown_variable(self, renderer: AlertExplanationRenderer):
        """Garante que o Jinja2 com StrictUndefined lança erro se uma variável inexistente for referenciada."""
        template_with_unknown = renderer.env.from_string("Olá {{ unknown_unprovided_var }}")
        with pytest.raises(UndefinedError):
            template_with_unknown.render()
