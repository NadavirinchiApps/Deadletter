# CDK sample

A small CDK app, used to check Deadletter against output a real `cdk synth`
produced rather than against a template written by hand to look like one.

Nothing in `bin/app.js` is contrived to trip a rule. It wires an event bus to a
handler, grants that handler write access to a provisioned table and permission
to publish back to the bus, and hands settlement to a state machine. CDK
expresses every one of those grants as an `AWS::IAM::Policy` resource and every
workflow definition as an `Fn::Join`, which is exactly the shape a template-only
scanner has to read to see the wiring at all.

```console
npm install
npx cdk synth          # writes cdk.out/
cd ../../..
deadletter docs/samples/cdk --fail-on none
```

`cdk.out` is generated and gitignored, as is `node_modules`. Deadletter finds
the stack through `cdk.out/manifest.json` rather than by walking the directory,
so only the templates the assembly declares are scanned — not the asset staging
copies beside them.

What that run produces today, on aws-cdk-lib 2.268.0:

| Rule | What it found | Construct |
|---|---|---|
| EDA002 | The rule target has no DLQ and the handler has no on-failure destination | `OrdersStack/OrderPlacedRule/Resource` |
| EDA004 | `bus -> Handler -> bus`, through the `grantPutEventsTo` policy | `OrdersStack/OrderPlacedRule/Resource` |
| EDA007 | An uncapped handler writing to a 5-WCU provisioned table | `OrdersStack/Handler/Resource` |
| EDA010 | `LambdaInvoke` retries four transient errors and not `Lambda.TooManyRequestsException` | `OrdersStack/SettlementWorkflow/Resource` |

Every finding names a construct path, because `Handler886CB40B` is not
something the author of `bin/app.js` can search for.
