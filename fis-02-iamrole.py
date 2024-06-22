import boto3

def get_resource_id(event_manager, service_manager, logs_manager):
    try:
        responseElements = event_manager.get_value('responseElements')
        experimentTemplate = responseElements["experimentTemplate"]
        Id = experimentTemplate["id"]
        roleARN = experimentTemplate.get("roleArn")  # Use .get() to handle missing keys gracefully
        logs_manager.info(f"FIS with {Id} has been identified. Resource Id has been recorded")
        return Id, roleARN, experimentTemplate
    except Exception as e:
        logs_manager.error(e)
        return None

def evaluate(resource_id, event_manager, service_manager, logs_manager, compliance):
    try:
        fis_client = service_manager.get_client("fis")
        iam_client = service_manager.get_client("iam")
        Id, roleARN, experimentTemplate = resource_id
        # Extract template_id and role_arn from resource_id
        role_name = roleARN.split('/')[-1]
        experiment_template = experimentTemplate
        
        # Initialize variables to store policy information
        aws_managed_policies = []
        inline_policy_actions = []
        inline_policy_resources_with_star = []
        customer_managed_policy_actions = []
        customer_managed_policy_resources_with_star = []
        extra_actions = set()
        
        # Get attached managed policies
        attached_policies = iam_client.list_attached_role_policies(RoleName=role_name)
        
        for policy in attached_policies['AttachedPolicies']:
            policy_arn = policy['PolicyArn']
            policy_info = iam_client.get_policy(PolicyArn=policy_arn)
            if policy_info['Policy']['Arn'].startswith('arn:aws:iam::aws:policy/'):
                # This is an AWS managed policy
                aws_managed_policies.append(policy_info['Policy']['PolicyName'])
            else:
                # This is a customer managed policy
                policy_version = policy_info['Policy']['DefaultVersionId']
                policy_document = iam_client.get_policy_version(PolicyArn=policy_arn, VersionId=policy_version)['PolicyVersion']['Document']
                for statement in policy_document['Statement']:
                    if 'Action' in statement:
                        actions = statement['Action']
                        if isinstance(actions, list):
                            customer_managed_policy_actions.extend(actions)
                        else:
                            customer_managed_policy_actions.append(actions)
                    if 'Resource' in statement:
                        resource = statement['Resource']
                        if resource == ["*"]:
                            customer_managed_policy_resources_with_star.append(policy_info['Policy']['PolicyName'])
        
        # Get inline policies
        inline_policies = iam_client.list_role_policies(RoleName=role_name)
        
        for policy_name in inline_policies['PolicyNames']:
            policy = iam_client.get_role_policy(RoleName=role_name, PolicyName=policy_name)
            policy_document = policy['PolicyDocument']
            
            policy_has_star_resource = False
            
            for statement in policy_document['Statement']:
                if 'Action' in statement:
                    actions = statement['Action']
                    if isinstance(actions, list):
                        inline_policy_actions.extend(actions)
                    else:
                        inline_policy_actions.append(actions)
                if 'Resource' in statement:
                    resource = statement['Resource']
                    if resource == "*":
                        policy_has_star_resource = True
            
            if policy_has_star_resource:
                inline_policy_resources_with_star.append(policy_name)
        
        # Compare actions with target_services
        target_services = set()
        for target in experiment_template['targets']:
            resource_type = target['resourceType']
            service_name = resource_type.split(':')[1]  # Extract service name
            target_services.add(service_name)
        
        for actions in [inline_policy_actions, customer_managed_policy_actions]:
            for action in actions:
                service = action.split(':')[0]
                if service not in target_services:
                    extra_actions.add(action)
        
        # Check conditions for compliance
        compliant = True
        
        # Condition 1: Check for AWS managed policies
        if aws_managed_policies:
            compliant = False
            print("test-1")
        
        # Condition 2: Check for extra actions
        if extra_actions:
            compliant = False
            print("test-2")
        
        # Condition 3: Check for * in customer managed policies or inline policies
        if inline_policy_resources_with_star or customer_managed_policy_resources_with_star:
            compliant = False
            print("test-3")
        
        # Determine compliance status
        compliance_status = 'Compliant' if compliant else 'Non-Compliant'
        print("test-4")
        
        # Update compliance and logs based on compliance status
        if compliant:
            compliance.update("COMPLIANT", f"FIS Experiment Template {Id} is compliant")
            logs_manager.info(f"FIS Experiment Template {Id} IAM role has only required permissions")
        else:
            compliance.update("NON-COMPLIANT", f"FIS Experiment Template {Id} is non-compliant")
            logs_manager.info(f"FIS Experiment Template {Id} IAM role is overly permissive")
        
        # Construct response
        # response_body = {
            # 'AWSManagedPolicies': aws_managed_policies,
            # 'InlinePolicyActions': inline_policy_actions,
            # 'InlinePolicyResourcesWithStar': inline_policy_resources_with_star,
            # 'CustomerManagedPolicyActions': customer_managed_policy_actions,
            # 'CustomerManagedPolicyResourcesWithStar': customer_managed_policy_resources_with_star,
            # 'ExtraActions': list(extra_actions),
            # 'ComplianceStatus': compliance_status
        # }
        # 
        # return {
            # 'statusCode': 200,
            # 'body': response_body
        # }
    
    except Exception as e:
        compliance.update("UNKNOWN", f"{e}")
        logs_manager.error(e)

def remediate(resource_id, event_manager, service_manager, logs_manager, remediation):
    fis_client = service_manager.get_client("fis")
    iam_client = service_manager.get_client("iam")
    roleARN, Id = resource_id
    try:
        response = fis_client.delete_experiment_template(id= Id)
        remediation.update("SUCCESS", f"FIS Experiment Template {Id} has been deleted")
        logs_manager.info(f"FIS Experiment Template {Id} has been deleted")
    except Exception as e:
        remediation.update("FAIL", f"{e}")
        logs_manager.error(e)
