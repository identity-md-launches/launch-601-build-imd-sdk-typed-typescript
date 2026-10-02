import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

const live = (name) =>
  readFile(new URL(`./fixtures/live/${name}.json`, import.meta.url), 'utf8').then(JSON.parse);
const declarations = await readFile(new URL('../src/index.d.ts', import.meta.url), 'utf8');

function requiredFields(interfaceName) {
  const match = declarations.match(
    new RegExp(`export interface ${interfaceName} \\{([\\s\\S]*?)\\n\\}`),
  );
  assert.ok(match, `${interfaceName} is exported`);
  return [...match[1].matchAll(/^  ([A-Za-z][A-Za-z0-9]*)(\\?)?:/gm)]
    .filter((field) => !field[2])
    .map((field) => field[1]);
}

function hasFields(value, fields, name) {
  for (const field of fields) {
    assert.ok(Object.hasOwn(value, field), `${name} fixture has required ${field}`);
  }
}

test('saved live bodies contain every declared required response field', async () => {
  const [capabilities, check, scheduleCheck, imported, job, schedules] = await Promise.all([
    live('capabilities'),
    live('check'),
    live('check-schedule-create'),
    live('import'),
    live('job'),
    live('schedules'),
  ]);

  hasFields(capabilities, requiredFields('Capabilities'), 'capabilities');
  hasFields(
    capabilities.authentication,
    requiredFields('CapabilitiesAuthentication'),
    'capabilities.authentication',
  );
  hasFields(capabilities.payment, requiredFields('CapabilitiesPayment'), 'capabilities.payment');
  for (const policy of capabilities.actions) {
    hasFields(policy, requiredFields('Policy'), 'capabilities.actions[]');
    hasFields(policy.payment, requiredFields('Payment'), 'capabilities.actions[].payment');
  }
  hasFields(check, requiredFields('CheckResult'), 'check');
  for (const fact of check.facts) {
    hasFields(fact, requiredFields('CheckFact'), 'check.facts[]');
  }
  for (const message of [...check.blockers, ...check.suggestions]) {
    hasFields(message, requiredFields('CheckMessage'), 'check message');
  }
  hasFields(scheduleCheck, requiredFields('CheckResult'), 'check schedule.create');
  hasFields(scheduleCheck, ['unitAmount', 'runs', 'amount', 'terms'], 'check schedule.create');
  assert.equal(scheduleCheck.runs, 7);
  assert.equal(BigInt(scheduleCheck.amount), BigInt(scheduleCheck.unitAmount) * 7n);
  for (const message of [...scheduleCheck.blockers, ...scheduleCheck.suggestions]) {
    hasFields(message, requiredFields('CheckMessage'), 'check schedule.create message');
  }
  hasFields(imported, requiredFields('ImportResult'), 'import');
  hasFields(imported.source, requiredFields('ImportSource'), 'import.source');
  hasFields(job, requiredFields('Job'), 'job');
  hasFields(schedules, requiredFields('SchedulesResult'), 'schedules');
  for (const schedule of schedules.schedules) {
    hasFields(schedule, requiredFields('Schedule'), 'schedules.schedules[]');
  }
});

test('declarations retain all required fields in the saved live OpenAPI schemas', async () => {
  const openapi = await live('openapi');
  const expected = {
    Policy: 'Policy',
    Quote: 'Quote',
    Order: 'Order',
    Status: 'OrderStatus',
    Challenge: 'Challenge',
  };

  for (const [schemaName, interfaceName] of Object.entries(expected)) {
    const schema = openapi.components.schemas[schemaName];
    assert.deepEqual(
      requiredFields(interfaceName).sort(),
      (schema.required ?? []).sort(),
      `${interfaceName} mirrors OpenAPI ${schemaName}.required`,
    );
  }
  assert.doesNotMatch(declarations, /Promise<any>/);
});
