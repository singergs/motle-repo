import subprocess
import boto3
import json
import time
import requests
import re
import argparse

def send_logs_to_cloudwatch_logs(log_group_name, log_stream_name, log_events, region_name='us-east-1'):
    print(f"Sending {log_events} to {log_group_name}")
    try:
        client = boto3.client('logs', region_name=region_name)
        timestamp = int(time.time() * 1000)
        response = client.put_log_events(
            logGroupName=log_group_name,
            logStreamName=log_stream_name,
            logEvents=[
                {
                    'timestamp': timestamp,
                    'message': log_events
                }
            ]
        )

    except Exception as e:
        print("Error sending log events to CloudWatch Logs:", e)

def get_service_status(service_name):
    try:
        # Run systemctl status command and capture the output
        output = subprocess.check_output(['systemctl', 'status', service_name
        ]).decode('utf-8')

        # Extract CPU and Memory information
        cpu_info = None
        memory_info = None
        for line in output.split('\n'):
            if "CPU:" in line:
                cpu_info = line.strip()
                match_cpu = re.search("CPU:\s(\d+)", cpu_info)
                cpu_info = match_cpu.group(1)
            elif "Memory:" in line:
                memory_info = line.strip()
                match_mem = re.search("Memory:\s(\d+)", memory_info)
                memory_info = match_mem.group(1)
            elif "Main PID:" in line:
                pid_info = line.strip()
                match_pid = re.search("Main PID:\s(\d+) \((\w+)\)", pid_info)
                pid_info = match_pid.group(1)+'-'+ match_pid.group(2)
                
                
                
        # Check if the service is active (running)
        if "Active: active (running)" in output:
            return True, cpu_info, memory_info, pid_info
        else:
            return False, cpu_info, memory_info
    except subprocess.CalledProcessError:
        # If the service is not found or there's an error, return False
        return False, None, None, None

def get_instance_info():
    try:
        response = requests.get("http://169.254.169.254/latest/meta-data/instance-id", timeout=0.1)
        if response.status_code == 200:
            return response.text
        else:
            print("Failed to retrieve instance ID. Status code:", response.status_code)
    except requests.RequestException as e:
        print("Error:", e)

def get_instance_tags(instance_id=None, instance_tag=None):    # Create EC2 client
    ec2_client = boto3.client('ec2')
    response = ec2_client.describe_instances(InstanceIds=[instance_id])
    tags = []
    for reservation in response['Reservations']:
        for instance in reservation['Instances']:
            tags.extend(instance.get('Tags', []))

    
    for tag in tags:
        if tag['Key'] == instance_tag:
            return(tag['Value'])

def get_service_parameter(node_type=None):
    ssm_client = boto3.client('ssm')
    try:
        # Retrieve parameter value from SSM
        response = ssm_client.get_parameter(Name=node_type)
        parameter_value = response['Parameter']['Value']
        
        return parameter_value

    except Exception as e:
        print(f"Error occurred while retrieving parameter '{node_type}': {e}")
        return None



def main():
    
    parser = argparse.ArgumentParser(description="Service Monitor Routines")
    parser.add_argument("--config", help="AWS SSM Parameter for configuration", default="/motle/service_monitor_config")
    args = parser.parse_args()
    
    
    motle_SERVICE_MONITR_CONFIG = args.config
    motle_monitor_config = json.loads(get_service_parameter(motle_SERVICE_MONITR_CONFIG))
    
    LOG_GROUP_NAME = motle_monitor_config['LogGroupName']
    LOG_STREAM_NAME = 'motle_services'
    
    instance_info = get_instance_info()
    instance_type = get_instance_tags(instance_id=instance_info, instance_tag=motle_monitor_config['ec2Tag'])
    
    
    for node_type, system_tag in motle_monitor_config.items():
        if node_type != 'ec2Tag' and instance_type==node_type:
            service_names = motle_monitor_config[node_type]
            print(f"Checking {node_type} services for {motle_monitor_config[node_type]}")
    
            for service_name in service_names:
                status, cpu, memory, pid_info = get_service_status(service_name)
                service_status = {}
                if status:
                    service_status = {  'service_name': service_name,
                                        'service_pid': pid_info, 
                                        'service_status': 'active',
                                        'service_cpu': cpu,
                                        'service_memory':memory,
                                        'instance_id': instance_info,
                                        'node_type': instance_type
                        }
                    
                else:
                    service_status = {'service_name': service_name,
                                    'instance_id': instance_info,
                                    'service_status': 'inactive',
                                    'node_type': instance_type
            
                    }
                    
    
                send_logs_to_cloudwatch_logs(LOG_GROUP_NAME, LOG_STREAM_NAME, json.dumps(service_status))
                

if __name__ == "__main__":
    main()
