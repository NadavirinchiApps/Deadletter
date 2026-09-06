// Run cdk-nag's AwsSolutions pack against a raw CloudFormation/SAM template.
//
// cdk-nag inspects a CDK construct tree, not a template file, so the template is
// pulled in with CfnInclude. That produces L1 constructs carrying the same
// properties the nag rules read, which is the closest honest equivalent to
// "what would cdk-nag have told this team".
//
// Annotations are read the documented way, via aws-cdk-lib/assertions.

const cdk = require("aws-cdk-lib");
const { CfnInclude } = require("aws-cdk-lib/cloudformation-include");
const { Aspects } = require("aws-cdk-lib");
const { Annotations } = require("aws-cdk-lib/assertions");
const { AwsSolutionsChecks } = require("cdk-nag");

const templatePath = process.argv[2];
if (!templatePath) {
  console.error("usage: node nag.js <template>");
  process.exit(2);
}

const app = new cdk.App();
const stack = new cdk.Stack(app, "BenchStack");

try {
  new CfnInclude(stack, "Included", { templateFile: templatePath });
} catch (err) {
  // SAM transforms and some intrinsics CfnInclude will not accept. Report the
  // reason rather than silently claiming cdk-nag found nothing.
  console.log(
    JSON.stringify([
      { ruleId: "__include_error__", message: String(err.message).slice(0, 400) },
    ])
  );
  process.exit(0);
}

Aspects.of(app).add(new AwsSolutionsChecks({ verbose: true }));

const findings = [];
try {
  const annotations = Annotations.fromStack(stack);
  for (const [kind, entries] of [
    ["error", annotations.findError("*", require("aws-cdk-lib/assertions").Match.anyValue())],
    ["warning", annotations.findWarning("*", require("aws-cdk-lib/assertions").Match.anyValue())],
  ]) {
    for (const entry of entries) {
      const text = String(entry.entry?.data ?? "");
      const match = text.match(/(AwsSolutions-[A-Za-z0-9]+)/);
      findings.push({
        ruleId: match ? match[1] : "unknown",
        level: kind,
        path: entry.id ?? "",
        message: text.slice(0, 300),
      });
    }
  }
} catch (err) {
  console.log(
    JSON.stringify([{ ruleId: "__harness_error__", message: String(err.message).slice(0, 400) }])
  );
  process.exit(0);
}

console.log(JSON.stringify(findings, null, 2));
