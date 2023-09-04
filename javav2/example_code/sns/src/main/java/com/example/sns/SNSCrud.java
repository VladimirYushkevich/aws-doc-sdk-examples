package com.example.sns;

import com.amazonaws.auth.policy.Condition;
import com.amazonaws.auth.policy.Policy;
import com.amazonaws.auth.policy.Principal;
import com.amazonaws.auth.policy.Resource;
import com.amazonaws.auth.policy.Statement;
import com.amazonaws.auth.policy.actions.SNSActions;
import com.amazonaws.auth.policy.conditions.ArnCondition;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import software.amazon.awssdk.auth.credentials.ProfileCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.sns.SnsClient;
import software.amazon.awssdk.services.sns.model.GetTopicAttributesRequest;
import software.amazon.awssdk.services.sns.model.GetTopicAttributesResponse;
import software.amazon.awssdk.services.sns.model.SetTopicAttributesRequest;
import software.amazon.awssdk.services.sns.model.SetTopicAttributesResponse;
import software.amazon.awssdk.services.sns.model.SnsException;

public class SNSCrud {

  public static final String AWS_SOURCE_ACCOUNT_CONDITION = "aws:SourceArn";
  public static final int NUMBER_OF_DUMMY_ACCOUNTS = 700;

  public static void main(String[] args) {
    long start = System.currentTimeMillis();

    final String usage =
        "\n"
            + "Usage: "
            + "   <topicArn> <accountId> <action>\n\n"
            + "Where:\n"
            + "   topicArn  - The ARN of the topic to look up.\n"
            + "   bucket    - The s3 bucket(unique for all accounts and regions) to grant/revoke permissions for pushing messages in topic.\n"
            + "   action    - GRANT|BULK_GRANT|REVOKE|DELETE.\n\n";

    if (args.length != 3) {
      System.out.println(usage);
      System.exit(1);
    }

    try (SnsClient snsClient =
        SnsClient.builder()
            .region(Region.US_WEST_2)
            .credentialsProvider(ProfileCredentialsProvider.create("qa-dataplane"))
            .build()) {
      String topicArn = args[0];
      String bucket = args[1];
      String action = args[2];
      switch (action) {
        case "GRANT":
          grantPermissions(snsClient, topicArn, buildBucketArn(bucket));
          break;
        case "BULK_GRANT":
          grantBulkPermissions(snsClient, topicArn, buildBucketArn(bucket));
          break;
        case "REVOKE":
          revokePermissions(snsClient, topicArn, buildBucketArn(bucket));
          break;
        case "DELETE":
          deleteStatement(snsClient, topicArn, buildBucketArn(bucket));
          break;
        default:
          System.out.println("Not valid action");
          System.exit(1);
      }
    } catch (SnsException e) {
      System.err.println(e.awsErrorDetails().errorMessage());
      System.exit(1);
    }

    long finish = System.currentTimeMillis();
    long timeElapsed = finish - start;
    System.out.println("timeElapsed: " + timeElapsed + " ms.");
  }

  private static void deleteStatement(SnsClient snsClient, String topicArn, String bucket) {
    Policy policy = getSnsPermissionPolicy(snsClient, topicArn);
    Collection<Statement> statements = policy.getStatements();
    Optional<Condition> maybeCondition = findCondition(statements);
    if (maybeCondition.isPresent()) {
      Condition condition = maybeCondition.get();
      if (condition.getValues().contains(bucket)) {
        Optional<Statement> maybeStatement = findStatement(statements, condition);
        if (maybeStatement.isPresent()) {
          statements.remove(maybeStatement.get());
          setTopicAttributes(snsClient, topicArn, policy);
          System.out.println("Removed statement with bucket=" + bucket);
        }
      } else {
        System.out.println("Bucket not found. Skip");
      }
    } else {
      System.out.println("Permission not found. Skip");
    }
  }

  private static void revokePermissions(SnsClient snsClient, String topicArn, String bucket) {
    Policy policy = getSnsPermissionPolicy(snsClient, topicArn);
    Collection<Statement> statements = policy.getStatements();
    Optional<Condition> maybeCondition = findCondition(statements);
    if (maybeCondition.isPresent()) {
      Condition condition = maybeCondition.get();
      if (condition.getValues().contains(bucket)) {
        List<String> conditionValues = condition.getValues();
        conditionValues.remove(bucket);
        if (conditionValues.isEmpty()) {
          Optional<Statement> maybeStatement = findStatement(statements, condition);
          if (maybeStatement.isPresent()) {
            statements.remove(maybeStatement.get());
            setTopicAttributes(snsClient, topicArn, policy);
            System.out.println("Removed statement with single bucket=" + bucket);
          }
        } else {
          setTopicAttributes(snsClient, topicArn, policy);
          System.out.println("Removed condition for bucket=" + bucket);
        }
      } else {
        System.out.println("Bucket not found. Skip");
      }
    } else {
      System.out.println("Permission not found. Skip");
    }
  }

  private static void grantBulkPermissions(SnsClient snsClient, String topicArn, String bucket) {
    Policy policy = getSnsPermissionPolicy(snsClient, topicArn);
    Collection<Statement> statements = policy.getStatements();
    Optional<Condition> maybeCondition = findCondition(statements);
    int start = 1;
    List<String> buckets =
        IntStream.range(start, start + NUMBER_OF_DUMMY_ACCOUNTS)
            .mapToObj(i -> String.format("%s-%s", bucket, i))
            .collect(Collectors.toList());
    if (maybeCondition.isPresent()) {
      Condition condition = maybeCondition.get();
      condition.getValues().addAll(buckets);
      setTopicAttributes(snsClient, topicArn, policy);
      System.out.println("Updated bulk condition for buckets=" + buckets);
    } else {
      statements.add(buildSnsGrantPermissionStatement(topicArn, buckets));
      setTopicAttributes(snsClient, topicArn, policy);
      System.out.println("Created bulk statement for buckets=" + buckets);
    }
  }

  private static void grantPermissions(SnsClient snsClient, String topicArn, String bucket) {
    Policy policy = getSnsPermissionPolicy(snsClient, topicArn);
    Collection<Statement> statements = policy.getStatements();
    Optional<Condition> maybeCondition = findCondition(statements);
    if (maybeCondition.isPresent()) {
      Condition condition = maybeCondition.get();
      if (condition.getValues().contains(bucket)) {
        System.out.println("Permission already exists. Skip");
      } else {
        condition.getValues().add(bucket);
        setTopicAttributes(snsClient, topicArn, policy);
        System.out.println("Updated condition for bucket=" + bucket);
      }
    } else {
      statements.add(buildSnsGrantPermissionStatement(topicArn, Collections.singletonList(bucket)));
      setTopicAttributes(snsClient, topicArn, policy);
      System.out.println("Created statement for bucket=" + bucket);
    }
  }

  private static Optional<Statement> findStatement(
      Collection<Statement> statements, Condition condition) {
    return statements.stream().filter(s -> s.getConditions().contains(condition)).findAny();
  }

  private static Optional<Condition> findCondition(Collection<Statement> statements) {
    return statements.stream()
        .flatMap(s -> s.getConditions().stream())
        .filter(c -> AWS_SOURCE_ACCOUNT_CONDITION.equals(c.getConditionKey()))
        .findAny();
  }

  private static void setTopicAttributes(SnsClient snsClient, String topicArn, Policy policy) {
    SetTopicAttributesRequest request =
        SetTopicAttributesRequest.builder()
            .attributeName("Policy")
            .attributeValue(policy.toJson())
            .topicArn(topicArn)
            .build();

    SetTopicAttributesResponse result = snsClient.setTopicAttributes(request);
    System.out.println(
        "\n\nStatus was "
            + result.sdkHttpResponse().statusCode()
            + "\n\nTopic "
            + request.topicArn()
            + " updated "
            + request.attributeName()
            + " to "
            + request.attributeValue());
  }

  private static Policy getSnsPermissionPolicy(SnsClient snsClient, String topicArn) {
    System.out.println("Getting attributes for a topic with name: " + topicArn);

    GetTopicAttributesRequest request =
        GetTopicAttributesRequest.builder().topicArn(topicArn).build();

    GetTopicAttributesResponse result = snsClient.getTopicAttributes(request);
    Map<String, String> attributes = result.attributes();
    return Policy.fromJson(attributes.get("Policy"));
  }

  private static Statement buildSnsGrantPermissionStatement(String topicArn, List<String> buckets) {
    Condition condition =
        new Condition()
            .withType(ArnCondition.ArnComparisonType.ArnEquals.toString())
            .withConditionKey(AWS_SOURCE_ACCOUNT_CONDITION)
            .withValues(buckets);
    return new Statement(Statement.Effect.Allow)
        .withId(
            UUID.randomUUID()
                .toString()) // we can set something meaningful here (SAGA request id for example)
        .withPrincipals(Principal.AllUsers)
        .withActions(SNSActions.Publish)
        .withResources(new Resource(topicArn))
        .withConditions(condition);
  }

  private static String buildBucketArn(String id) {
    return String.format("arn:aws:s3:::%s", id);
  }
}
