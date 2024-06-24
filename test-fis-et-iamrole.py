def evaluate(resource_id, event_manager, service_manager, logs_manager, compliance):
    try:
        fis_client = service_manager.get_client("fis")
        iam_client = service_manager.get_client("iam")
        
        Id, roleARN, experimentTemplate = resource_id

        if roleARN is None:
            logs_manager.error("roleARN is None")
            return

        role_name = roleARN.split('/')[-1]
        
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
                        if isinstance(resource, list) and "*" in resource:
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
        for target_key, target in experimentTemplate.get('targets', {}).items():
            resource_type = target.get('resourceType', '')
            if resource_type:
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
        
        # Condition 2: Check for extra actions
        if extra_actions:
            compliant = False
        
        # Condition 3: Check for * in customer managed policies or inline policies
        if inline_policy_resources_with_star or customer_managed_policy_resources_with_star:
            compliant = False
        
        # Determine compliance status
        compliance_status = 'Compliant' if compliant else 'Non-Compliant'
        
        # Update compliance and logs based on compliance status
        if compliant:
            compliance.update("COMPLIANT", f"FIS Experiment Template {Id} is compliant")
            logs_manager.info(f"FIS Experiment Template {Id} IAM role has only required permissions")
        else:
            compliance.update("NON-COMPLIANT", f"FIS Experiment Template {Id} is non-compliant")
            logs_manager.info(f"FIS Experiment Template {Id} IAM role is overly permissive")
        
    except Exception as e:
        compliance.update("UNKNOWN", f"{e}")
        logs_manager.error(e)
