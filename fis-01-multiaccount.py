import boto3

def get_resource_id(event_manager, service_manager, logs_manager):
    try:
        responseElements = event_manager.get_value("responseElements")
        Id = responseElements["experimentTemplate"]["id"]
        #roleARN = responseElements["experimentTemplate"]["roleArn"]
        logs_manager.info(f"FIS with {Id} has been identified. Resource Id has been recorded")
        return Id
    except Exception as e:
        logs_manager.error(e)
        return "UNKNOWN"
    
def evaluate(resource_id, event_manager, service_manager, logs_manager, compliance):
    fis_client = service_manager.get_client("fis")
    try:
       response = fis_client.get_experiment_template(id= resource_id)
       options = response['experimentTemplate']['experimentOptions']['accountTargeting']
       if options == "multi-account":
            compliance.update("NON-COMPLIANT", f"FIS Experiment Template {resource_id} is created in multi account mode")
            logs_manager.info(f"FIS Experiment Template {resource_id} has account targetting as multi account")
       else:
            compliance.update("COMPLIANT", f"FIS Experiment Template {resource_id} is not created in multio account mode")
            logs_manager.info(f"FIS Experiment Template {resource_id} does not have targetting as multi account")
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
