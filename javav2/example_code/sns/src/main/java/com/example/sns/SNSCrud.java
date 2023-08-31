package com.example.sns;

import com.amazonaws.auth.policy.Policy;
import com.amazonaws.auth.policy.Principal;
import com.amazonaws.auth.policy.Resource;
import com.amazonaws.auth.policy.Statement;
import com.amazonaws.auth.policy.actions.SNSActions;
import com.amazonaws.auth.policy.conditions.ArnCondition;
import com.amazonaws.auth.policy.conditions.StringCondition;
import software.amazon.awssdk.auth.credentials.ProfileCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.sns.SnsClient;
import software.amazon.awssdk.services.sns.model.GetTopicAttributesRequest;
import software.amazon.awssdk.services.sns.model.GetTopicAttributesResponse;
import software.amazon.awssdk.services.sns.model.SetTopicAttributesRequest;
import software.amazon.awssdk.services.sns.model.SetTopicAttributesResponse;
import software.amazon.awssdk.services.sns.model.SnsException;

import java.util.Collection;
import java.util.Map;

public class SNSCrud {
    public static void main(String[] args) {

        final String usage = "\n" +
                "Usage: " +
                "   <topicArn> <accountId> <action>\n\n" +
                "Where:\n" +
                "   topicArn  - The ARN of the topic to look up.\n" +
                "   accountId - The id of account to grant/revoke permissions for pushing messages in topic.\n" +
                "   action    - GRANT|REVOKE.\n\n";

        if (args.length != 3) {
            System.out.println(usage);
            System.exit(1);
        }

        SnsClient snsClient = SnsClient.builder()
                .region(Region.US_WEST_2)
                .credentialsProvider(ProfileCredentialsProvider.create("qa-dataplane"))
                .build();

        String topicArn = args[0];
        String awsAccountId = args[1];
        String action = args[2];
        try {
            switch (action) {
                case "GRANT":
                    grantPermissions(snsClient, topicArn, awsAccountId);
                    break;
                case "REVOKE":
                    revokePermissions(snsClient, topicArn, awsAccountId);
                    break;
                default:
                    System.out.println("Not valid action");
                    System.exit(1);
            }
        } catch (SnsException e) {
            System.err.println(e.awsErrorDetails().errorMessage());
            System.exit(1);
        } finally {
            snsClient.close();
        }
    }

    private static void revokePermissions(SnsClient snsClient, String topicArn, String awsAccountId) {
        Policy policy = getSnsPermissionPolicy(snsClient, topicArn);
        Collection<Statement> statements = policy.getStatements();
        if (statements.stream().anyMatch(s -> awsAccountId.equals(s.getId()))) {
            statements.removeIf(s -> awsAccountId.equals(s.getId()));
            setTopicAttributes(snsClient, topicArn, policy);
        } else {
            System.out.println("Permission not found. Skip");
        }
    }

    private static void grantPermissions(SnsClient snsClient, String topicArn, String awsAccountId) {
        Policy policy = getSnsPermissionPolicy(snsClient, topicArn);
        Collection<Statement> statements = policy.getStatements();
        if (statements.stream().anyMatch(s -> awsAccountId.equals(s.getId()))) {
            System.out.println("Permission already exists. Skip");
        } else {
            statements.add(buildSnsGrantPermissionStatement(topicArn, awsAccountId));
            setTopicAttributes(snsClient, topicArn, policy);
        }
    }

    private static void setTopicAttributes(SnsClient snsClient, String topicArn, Policy policy) {
        SetTopicAttributesRequest request = SetTopicAttributesRequest.builder()
                .attributeName("Policy")
                .attributeValue(policy.toJson())
                .topicArn(topicArn)
                .build();

        SetTopicAttributesResponse result = snsClient.setTopicAttributes(request);
        System.out.println("\n\nStatus was " + result.sdkHttpResponse().statusCode() + "\n\nTopic " + request.topicArn()
                + " updated " + request.attributeName() + " to " + request.attributeValue());
    }

    private static Policy getSnsPermissionPolicy(SnsClient snsClient, String topicArn) {
        System.out.println("Getting attributes for a topic with name: " + topicArn);

        GetTopicAttributesRequest request = GetTopicAttributesRequest.builder()
                .topicArn(topicArn)
                .build();

        GetTopicAttributesResponse result = snsClient.getTopicAttributes(request);
        Map<String, String> attributes = result.attributes();
        return Policy.fromJson(attributes.get("Policy"));
    }

    private static Statement buildSnsGrantPermissionStatement(String topicArn, String accountId) {
        return new Statement(Statement.Effect.Allow)
                .withId(accountId) // we can set something meaningful here for quick lookup
                .withPrincipals(Principal.AllUsers)
                .withActions(SNSActions.Publish)
                .withResources(new Resource(topicArn))
                .withConditions(new StringCondition(StringCondition.StringComparisonType.StringEquals, "aws:SourceAccount", accountId),
                        new ArnCondition(ArnCondition.ArnComparisonType.ArnLike, "aws:SourceArn", "arn:aws:s3:*:*:*"));
    }
}
