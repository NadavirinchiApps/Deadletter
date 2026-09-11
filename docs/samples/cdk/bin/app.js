// A small CDK app whose synthesized output Deadletter is checked against.
//
// Nothing here is contrived to trip a rule. It is the shape a team writes when
// they wire an event bus to a handler that writes to a table and hands work to
// a workflow — the point is that CDK expresses every one of those grants as a
// separate AWS::IAM::Policy, which is exactly what a template-only scanner has
// to read to see the wiring at all.
const { App, Stack, Duration } = require("aws-cdk-lib");
const events = require("aws-cdk-lib/aws-events");
const targets = require("aws-cdk-lib/aws-events-targets");
const lambda = require("aws-cdk-lib/aws-lambda");
const dynamodb = require("aws-cdk-lib/aws-dynamodb");
const sfn = require("aws-cdk-lib/aws-stepfunctions");
const tasks = require("aws-cdk-lib/aws-stepfunctions-tasks");

class OrdersStack extends Stack {
  constructor(scope, id, props) {
    super(scope, id, props);

    const bus = new events.EventBus(this, "OrdersBus", { eventBusName: "orders" });

    const table = new dynamodb.Table(this, "OrdersTable", {
      partitionKey: { name: "pk", type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PROVISIONED,
      readCapacity: 5,
      writeCapacity: 5,
    });

    const handler = new lambda.Function(this, "Handler", {
      runtime: lambda.Runtime.NODEJS_22_X,
      handler: "index.handler",
      code: lambda.Code.fromInline("exports.handler = async () => {};"),
      timeout: Duration.seconds(30),
    });

    // The two grants that make this stack interesting: the handler may write
    // to the table it is sized against, and may publish back to the bus that
    // invokes it. CDK writes both into one AWS::IAM::Policy resource.
    table.grantWriteData(handler);
    bus.grantPutEventsTo(handler);

    new events.Rule(this, "OrderPlacedRule", {
      eventBus: bus,
      eventPattern: { source: ["orders"] },
      targets: [new targets.LambdaFunction(handler)],
    });

    const settle = new lambda.Function(this, "Settle", {
      runtime: lambda.Runtime.NODEJS_22_X,
      handler: "index.settle",
      code: lambda.Code.fromInline("exports.handler = async () => {};"),
      timeout: Duration.seconds(15),
    });

    new sfn.StateMachine(this, "SettlementWorkflow", {
      definitionBody: sfn.DefinitionBody.fromChainable(
        new tasks.LambdaInvoke(this, "Settle payment", { lambdaFunction: settle })
      ),
    });
  }
}

const app = new App();
new OrdersStack(app, "OrdersStack", { env: { account: "123456789012", region: "us-east-1" } });
app.synth();
