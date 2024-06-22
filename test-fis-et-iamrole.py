import boto3

def get_iam_role_policies(role_name, target_services):
    # Create an IAM client
    iam_client = boto3.client('iam')
    
    # Initialize variables to store policy information
    inline_policy_actions = []
    customer_managed_policy_actions = []
    inline_policy_resources_with_star = []
    customer_managed_policy_resources_with_star = []
    
    # Get attached managed policies
    attached_policies = iam_client.list_attached_role_policies(RoleName=role_name)
    
    for policy in attached_policies['AttachedPolicies']:
        policy_arn = policy['PolicyArn']
        policy_info = iam_client.get_policy(PolicyArn=policy_arn)
        if policy_info['Policy']['Arn'].startswith('arn:aws:iam::aws:policy/'):
            # Skip AWS managed policies
            continue
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
                if 'Resource' in statement and statement['Resource'] == '*':
                    customer_managed_policy_resources_with_star.append(policy_info['Policy']['PolicyName'])
    
    # Get inline policies
    inline_policies = iam_client.list_role_policies(RoleName=role_name)
    
    for policy_name in inline_policies['PolicyNames']:
        policy = iam_client.get_role_policy(RoleName=role_name, PolicyName=policy_name)
        policy_document = policy['PolicyDocument']
        
        for statement in policy_document['Statement']:
            if 'Action' in statement:
                actions = statement['Action']
                if isinstance(actions, list):
                    inline_policy_actions.extend(actions)
                else:
                    inline_policy_actions.append(actions)
            if 'Resource' in statement and statement['Resource'] == '*':
                inline_policy_resources_with_star.append(policy_name)
    
    # Compare actions with target_services
    extra_actions = set()
    for actions in [inline_policy_actions, customer_managed_policy_actions]:
        for action in actions:
            service = action.split(':')[0]
            if service not in target_services:
                extra_actions.add(action)
    
    return {
        'InlinePolicyActions': inline_policy_actions,
        'InlinePolicyResourcesWithStar': inline_policy_resources_with_star,
        'CustomerManagedPolicyActions': customer_managed_policy_actions,
        'CustomerManagedPolicyResourcesWithStar': customer_managed_policy_resources_with_star,
        'ExtraActions': list(extra_actions)
    }

def get_role_and_targets_from_fis_template(template_id):
    # Create an FIS client
    fis_client = boto3.client('fis')
    
    # Get the FIS experiment template
    template_details = fis_client.get_experiment_template(id=template_id)
    
    # Extract the role ARN from the template
    role_arn = template_details['experimentTemplate']['roleArn']
    
    # Extract the role name from the ARN
    role_name = role_arn.split('/')[-1]
    
    # Extract targets and their resource types
    targets = template_details['experimentTemplate']['targets']
    services_set = set()  # Use a set to store unique services
    
    for target_id, target_info in targets.items():
        resource_type = target_info['resourceType']
        service_name = resource_type.split(':')[1]  # Extract service name
        services_set.add(service_name)
    
    target_services = list(services_set)  # Convert set back to list
    
    return role_name, target_services

def lambda_handler(event, context):
    template_id = 'EXT3RQhWP2iJToN'
    if not template_id:
        return {
            'statusCode': 400,
            'body': 'template_id is required in the event input'
        }
    
    role_name, target_services = get_role_and_targets_from_fis_template(template_id)
    if not role_name:
        return {
            'statusCode': 500,
            'body': 'Failed to retrieve role name from FIS template'
        }
    
    try:
        policies_info = get_iam_role_policies(role_name, target_services)
        return {
            'statusCode': 200,
            'body': policies_info
        }
    except Exception as e:
        return {
            'statusCode': 500,
            'body': str(e)
        }

# This lambda_handler function is the entry point for AWS Lambda execution.
