import pandas as pd
from sklearn.ensemble import IsolationForest
from secops_core.lgms import LGMSProcessor  # Importa o nosso módulo anterior

def run_anomaly_detection():
    print("Iniciando o pipeline de detecção de anomalias...")
    
    # 1. Carrega e processa os dados usando o LGMS
    processor = LGMSProcessor(filepath="data/logs_simulados.jsonl")
    processor.parse_file()
    df = processor.get_feature_matrix()
    
    if df.empty:
        print("Nenhum dado disponível para análise.")
        return

    # 2. Seleciona as features numéricas para o Machine Learning
    # O Isolation Forest usa matemática pura, então alimentamos ele com números
    features_para_ml = ['hour_of_day', 'day_of_week', 'is_error', 'ip_freq_count', 'bytes_transferred']
    X = df[features_para_ml]

    # 3. Configura e treina o modelo Isolation Forest
    # contamination=0.05 assume que cerca de 5% dos nossos dados podem ser anomalias
    model = IsolationForest(contamination=0.05, random_state=42)
    
    # O modelo retorna -1 para pontos isolados (anomalias) e 1 para pontos normais
    df['anomaly_score'] = model.fit_predict(X)
    df['is_anomaly'] = df['anomaly_score'].apply(lambda x: 1 if x == -1 else 0)

    # 4. Filtra apenas o que foi considerado suspeito
    anomalias = df[df['is_anomaly'] == 1]
    
    print("\n---------------------------------------------------")
    print(f"📊 Relatório Final de Segurança:")
    print(f"- Total de logs analisados: {len(df)}")
    print(f"- Anomalias detectadas pelo motor de ML: {len(anomalias)}")
    print("---------------------------------------------------")
    
    if not anomalias.empty:
        print("\nAmostra dos eventos mais suspeitos encontrados:")
        print(anomalias[['timestamp', 'event_name', 'user_arn', 'source_ip', 'bytes_transferred']].head())

if __name__ == "__main__":
    run_anomaly_detection()