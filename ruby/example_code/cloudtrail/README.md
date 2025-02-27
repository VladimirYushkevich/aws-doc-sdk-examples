# CloudTrail code examples for the SDK for Ruby
## Overview
These examples show how to create and manage AWS CloudTrail trails using the SDK for Ruby.

CloudTrail allows you to monitor your AWS deployments in the cloud by getting a history of AWS API calls for your account.

## ⚠️ Important
* Running this code might result in charges to your AWS account. 
* Running the tests might result in charges to your AWS account.
* We recommend that you grant your code least privilege. At most, grant only the minimum permissions required to perform the task. For more information, see [Grant least privilege](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#grant-least-privilege). 
* This code is not tested in every AWS Region. For more information, see [AWS Regional Services](https://aws.amazon.com/about-aws/global-infrastructure/regional-product-services).

## Code examples

### Single actions
Code excerpts that show you how to call individual service functions.

* [Create a trail](./create_trail.rb) (`CreateTrail`)

* [Delete a trail](./delete_trail.rb) (`DeleteTrail`)

* [Describe trails](./describe_trails.rb) (`DescribeTrails`)

* [Lookup events](./lookup_events.rb) (`LookupEvents`)






## Run the examples

### Prerequisites

See the [Ruby README.md](../../../ruby/README.md) for prerequisites.

### Instructions
The easiest way to interact with this example code is by invoking [Single Actions](#single-actions) from your command line. This may require some modification to override hard-coded values, and some actions also expect runtime parameters. For example, `ruby some_action.rb ARG1 ARG2` will invoke `some_action.rb` with two arguments.

### Tests
<!--custom.tests.start-->
The example code in this directory is not currently tested.

## Contribute
Code examples thrive on community contribution.

To learn more about the contributing process, see [CONTRIBUTING.md](../../../CONTRIBUTING.md).
<!--custom.tests.end-->

## Additional resources
<!--custom.resources.start-->
* [More Ruby CloudTrail code examples](https://docs.aws.amazon.com/sdk-for-ruby/v3/developer-guide/cloud-trail-examples.html)
* [SDK for Ruby Developer Guide](https://aws.amazon.com/developer/language/ruby/)
* [SDK for Ruby CloudTrail Module](https://docs.aws.amazon.com/sdk-for-ruby/v3/api/Aws/CloudTrail.html)
* [CloudTrail User Guide](https://docs.aws.amazon.com/cloudtrail/)
* [CodeTrail API Reference](https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/Welcome.html)
<!--custom.resources.end-->


---

Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0