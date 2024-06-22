for policy_name in inline_policies['PolicyNames']:
    policy = iam_client.get_role_policy(RoleName=role_name, PolicyName=policy_name)
    policy_document = policy['PolicyDocument']
    
    statements = policy_document.get('Statement', [])
    
    if not isinstance(statements, list):
        statements = [statements]  # Ensure statements is always a list
    
    policy_has_star_resource = False
    
    for statement in statements:
        if isinstance(statement, dict):  # Ensure statement is a dictionary
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
