import argparse
import json
import random
import uuid
from datetime import datetime, timedelta

# Referências de Base
REGIONS = ['us-east-1', 'sa-east-1', 'us-west-2']
NORMAL_IPS = ['192.168.1.50', '10.0.0.15', '172.16.0.5', '203.0.113.10']
ANOMALOUS_IPS = ['185.15.59.22', '45.33.32.156', '103.25.10.1']
USERS = ['alice', 'bob', 'charlie', 'svc-app']

NORMAL_EVENTS = [
    ('s3.amazonaws.com', 'GetObject'),
    ('s3.amazonaws.com', 'ListBuckets'),
    ('ec2.amazonaws.com', 'DescribeInstances'),
    ('signin.amazonaws.com', 'ConsoleLogin')
]

def generate_base_event(timestamp, is_anomaly=False):
    event_source, event_name = random.choice(NORMAL_EVENTS)
    source_ip = random.choice(ANOMALOUS_IPS) if is_anomaly else random.choice(NORMAL_IPS)
    
    return {
        "timestamp": timestamp.isoformat() + "Z",
        "event_id": str(uuid.uuid4()),
        "event_name": event_name,
        "event_source": event_source,
        "user_identity": {"arn": f"arn:aws:iam::123456789012:user/{random.choice(USERS)}"},
        "source_ip": source_ip,
        "aws_region": random.choice(REGIONS),
        "status": "Success",
        "error_code": None,
        "request_count": random.randint(1, 10),
        "bytes_transferred": random.randint(100, 5000)
    }

def generate_logs(num_records=1000, seed=42, anomaly_rate=0.05, output_file='data/logs_simulados.jsonl'):
    random.seed(seed)
    
    start_time = datetime(2026, 11, 4, 8, 0, 0)
    current_time = start_time
    
    logs = []
    
    for _ in range(num_records):
        current_time += timedelta(seconds=random.randint(1, 60))
        
        # Decide se vai injetar anomalia neste momento
        is_anomaly = random.random() < anomaly_rate
        
        if not is_anomaly:
            # Horário comercial para tráfego normal (8h as 18h)
            if current_time.hour < 8 or current_time.hour > 18:
                current_time = current_time.replace(hour=random.randint(8, 17))
            
            event = generate_base_event(current_time)
            # Falha ocasional no login
            if event['event_name'] == 'ConsoleLogin' and random.random() < 0.1:
                event['status'] = 'Failure'
                event['error_code'] = 'AccessDenied'
            logs.append(event)
        else:
            scenario = random.randint(1, 5)
            
            if scenario == 1: # 1. Brute Force (Rajada de falhas de login do mesmo IP)
                user = random.choice(USERS)
                ip = random.choice(ANOMALOUS_IPS)
                for _ in range(5):
                    current_time += timedelta(seconds=1)
                    ev = generate_base_event(current_time, True)
                    ev.update({"event_name": "ConsoleLogin", "event_source": "signin.amazonaws.com", 
                               "status": "Failure", "error_code": "AccessDenied", "source_ip": ip})
                    ev["user_identity"]["arn"] = f"arn:aws:iam::123456789012:user/{user}"
                    logs.append(ev)
            
            elif scenario == 2: # 2. Privilege Escalation (Alteração de permissões IAM)
                ev = generate_base_event(current_time, True)
                ev.update({"event_name": "PutUserPolicy", "event_source": "iam.amazonaws.com"})
                logs.append(ev)
                
            elif scenario == 3: # 3. Evasion (Tentativa de apagar rastros)
                ev = generate_base_event(current_time, True)
                ev.update({"event_name": "DeleteTrail", "event_source": "cloudtrail.amazonaws.com"})
                logs.append(ev)
                
            elif scenario == 4: # 4. Off-hours Access (Atividade na madrugada)
                off_time = current_time.replace(hour=random.randint(2, 4))
                ev = generate_base_event(off_time)
                ev.update({"event_name": "DescribeInstances", "event_source": "ec2.amazonaws.com", "source_ip": random.choice(NORMAL_IPS)})
                logs.append(ev)
                
            elif scenario == 5: # 5. Data Exfiltration (Volume anômalo)
                ev = generate_base_event(current_time, True)
                ev.update({"event_name": "GetObject", "event_source": "s3.amazonaws.com", 
                           "bytes_transferred": random.randint(500000, 9999999), # Mega/Giga de transferência
                           "request_count": random.randint(500, 2000)})
                logs.append(ev)
                
    # Ordenar pelo tempo e cortar para o tamanho exato solicitado
    logs = sorted(logs, key=lambda x: x["timestamp"])[:num_records]
    
    with open(output_file, 'w') as f:
        for log in logs:
            f.write(json.dumps(log) + '\n')
            
    print(f"Sucesso: {len(logs)} eventos gerados em {output_file}")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Gerador de Logs de SecOps')
    parser.add_argument('--num-records', type=int, default=1000)
    parser.add_argument('--seed', type=int, default=42)
    parser.add_argument('--anomaly-rate', type=float, default=0.05)
    parser.add_argument('--output', type=str, default='data/logs_simulados.jsonl')
    
    args = parser.parse_args()
    generate_logs(args.num_records, args.seed, args.anomaly_rate, args.output)
