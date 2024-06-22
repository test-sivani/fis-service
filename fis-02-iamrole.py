
import boto3
import json

def get_resource_id(event_manager, service_manager, logs_manager):
    try:
        responseElements = event_manager.get_value("responseElements")
        print(responseElements)
        experimentTemplate = responseElements["experimentTemplate"]
        print(experimentTemplate)
        Id = experimentTemplate["id"]
        print(Id)
        roleARN = experimentTemplate["roleArn"]
        print(roleARN)
        logs_manager.info(f"FIS with {Id} has been identified. Resource Id has been recorded")
        return Id, roleARN
    except Exception as e:
        logs_manager.error(e)
        return "UNKNOWN"
    
def evaluate(resource_id, event_manager, service_manager, logs_manager, compliance):
    try:
        fis_client = service_manager.get_client("fis")
        iam_client = service_manager.get_client("iam")
        Id, roleARN = resource_id
        role_name = roleARN.split("/")[-1]
        response = fis_client.get_experiment_template(id= Id)
        target_actions = response['experimentTemplate']['targets']
        managed_policies = iam_client.list_attached_role_policies(RoleName=role_name)
        inline_policies = iam_client.list_role_policies(RoleName=role_name)
        

                        
    except Exception as e:
        compliance.update("UNKNOWN", f"{e}")
        logs_manager.error(e)

def remediate(resource_id, event_manager, service_manager, logs_manager, remediation):
    fis_client = service_manager.get_client("fis")
    try:
        response = fis_client.delete_experiment_template(id= resource_id)
        remediation.update("SUCCESS", f"FIS Experiment Template {resource_id} has been deleted")
        logs_manager.info(f"FIS Experiment Template {resource_id} has been deleted")
    except Exception as e:
        remediation.update("FAIL", f"{e}")
        logs_manager.error(e)
