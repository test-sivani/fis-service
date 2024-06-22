import boto3

def get_iam_role_policies(role_name):
    # Create an IAM client
    iam_client = boto3.client('iam')
    
    # Initialize variables to store policy information
    aws_managed_policies = []
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
    
    return {
        'AWSManagedPolicies': aws_managed_policies,
        'InlinePolicyActions': inline_policy_actions,
        'InlinePolicyResourcesWithStar': inline_policy_resources_with_star,
        'CustomerManagedPolicyActions': customer_managed_policy_actions,
        'CustomerManagedPolicyResourcesWithStar': customer_managed_policy_resources_with_star
    }

def lambda_handler(event, context):
    # Set the role name directly for testing
    role_name = 'test_sivani'
    
    try:
        policies_info = get_iam_role_policies(role_name)
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
