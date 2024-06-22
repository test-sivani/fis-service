# fis-service

python code to check for the AWS IAM role

Check the IAM role for aws managed policies and inline policies, customer managed.Assign them to differnet variable and print them

In the managed policies get the policyname field and assign to variable. if multiple managed policies append and make it as one variable
in the inline policies get all the actions and assign to a variable. if multiple permissions append it and make as one variable
in the customer managed get all the actions and assign to a variable. if multiple permissions append it and make as one variable
and for the inline policy and customer managed in addition to actions check for Resource filed if it has *
after this return all the appended aws managed, customer managed and inline policies, 

