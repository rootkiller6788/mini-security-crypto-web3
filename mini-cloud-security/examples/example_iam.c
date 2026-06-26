#include "iam_policy.h"
#include <stdio.h>

int main(void) {
    printf("=== IAM Policy Engine Demo ===\n\n");

    iam_policy_t *admin_policy = iam_policy_create("AdministratorAccess", IAM_POLICY_IDENTITY);
    iam_policy_add_statement(admin_policy, IAM_EFFECT_ALLOW, "*", "*");
    printf("[1] Created policy: %s\n", admin_policy->name);

    iam_policy_t *s3_policy = iam_policy_create("S3ReadOnly", IAM_POLICY_IDENTITY);
    iam_policy_add_statement(s3_policy, IAM_EFFECT_ALLOW, "s3:GetObject", "arn:aws:s3:::my-bucket/*");
    iam_policy_add_statement(s3_policy, IAM_EFFECT_ALLOW, "s3:ListBucket", "arn:aws:s3:::my-bucket");
    printf("[2] Created policy: %s\n", s3_policy->name);

    iam_policy_t *deny_policy = iam_policy_create("DenyS3Delete", IAM_POLICY_IDENTITY);
    iam_policy_add_statement(deny_policy, IAM_EFFECT_DENY, "s3:DeleteObject", "arn:aws:s3:::my-bucket/*");
    printf("[3] Created policy: %s\n", deny_policy->name);

    iam_policy_t *scp = iam_policy_create("BlockS3Public", IAM_POLICY_SCP);
    iam_policy_add_statement(scp, IAM_EFFECT_DENY, "s3:PutBucketPolicy", "*");
    iam_policy_add_statement(scp, IAM_EFFECT_DENY, "s3:PutBucketAcl", "*");
    printf("[4] Created SCP: %s\n", scp->name);

    iam_policy_t *boundary = iam_policy_create("DevBoundary", IAM_POLICY_PERMISSION_BOUNDARY);
    iam_policy_add_statement(boundary, IAM_EFFECT_ALLOW, "s3:GetObject", "*");
    iam_policy_add_statement(boundary, IAM_EFFECT_ALLOW, "ec2:Describe*", "*");
    iam_policy_add_statement(boundary, IAM_EFFECT_ALLOW, "lambda:InvokeFunction", "*");
    printf("[5] Created Permission Boundary: %s\n\n", boundary->name);

    printf("--- Policy Evaluation Tests ---\n\n");

    iam_result_t r;
    r = iam_evaluate_policy(admin_policy, "s3:GetObject", "arn:aws:s3:::my-bucket/file.txt", NULL);
    printf("Admin + s3:GetObject  => %s\n", iam_result_to_string(r));

    r = iam_evaluate_policy(s3_policy, "s3:GetObject", "arn:aws:s3:::my-bucket/file.txt", NULL);
    printf("S3ReadOnly + GetObject => %s\n", iam_result_to_string(r));

    r = iam_evaluate_policy(s3_policy, "s3:DeleteObject", "arn:aws:s3:::my-bucket/file.txt", NULL);
    printf("S3ReadOnly + DeleteObject => %s\n", iam_result_to_string(r));

    r = iam_evaluate_policy(deny_policy, "s3:DeleteObject", "arn:aws:s3:::my-bucket/file.txt", NULL);
    printf("DenyS3Delete + DeleteObject => %s\n", iam_result_to_string(r));

    const iam_policy_t *combined[] = {s3_policy, deny_policy};
    r = iam_evaluate_all(combined, 2, "s3:DeleteObject", "arn:aws:s3:::my-bucket/file.txt", NULL);
    printf("S3ReadOnly+DenyS3Delete + DeleteObject => %s (explicit deny wins)\n",
           iam_result_to_string(r));

    printf("\n--- SCP Evaluation ---\n");
    r = iam_evaluate_scp(scp, "s3:PutBucketPolicy", "arn:aws:s3:::my-bucket", NULL);
    printf("SCP + s3:PutBucketPolicy => %s\n", iam_result_to_string(r));
    r = iam_evaluate_scp(scp, "s3:GetObject", "arn:aws:s3:::my-bucket", NULL);
    printf("SCP + s3:GetObject => %s\n", iam_result_to_string(r));

    iam_result_t base = iam_evaluate_policy(s3_policy, "lambda:InvokeFunction",
                                             "arn:aws:lambda:us-east-1:123456789012:function:my-func", NULL);
    printf("\n--- Permission Boundary ---\n");
    printf("S3ReadOnly + lambda:InvokeFunction => %s (base)\n", iam_result_to_string(base));
    r = iam_check_permission_boundary(base, boundary, "lambda:InvokeFunction",
                                       "arn:aws:lambda:us-east-1:123456789012:function:my-func", NULL);
    printf("After boundary check => %s\n", iam_result_to_string(r));

    printf("\n--- AssumeRole ---\n");
    iam_role_t *role = iam_role_create("LambdaExecutionRole",
        "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"Service\":\"lambda.amazonaws.com\"},\"Action\":\"sts:AssumeRole\"}]}", 3600);
    iam_role_attach_policy(role, 2);
    printf("Created Role: %s (ARN: %s)\n", role->name, role->arn);

    iam_session_t *session = iam_assume_role(role,
        "arn:aws:iam::123456789012:user/admin", 1800);
    if (session) {
        printf("Session created for: %s\n", session->assumed_role_arn);
        printf("Principal: %s\n", session->principal_arn);
        printf("Expiration: %lld (epoch)\n", (long long)session->expiration);
        iam_session_free(session);
    }

    iam_role_free(role);
    iam_policy_free(admin_policy);
    iam_policy_free(s3_policy);
    iam_policy_free(deny_policy);
    iam_policy_free(scp);
    iam_policy_free(boundary);

    printf("\nAll IAM tests complete.\n");
    return 0;
}
