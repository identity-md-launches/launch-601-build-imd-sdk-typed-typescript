// Install viem in your application first: npm i viem
import { createClient } from "imd-sdk";
import { privateKeyToAccount } from "viem/accounts";

const privateKey = process.env.IMD_PRIVATE_KEY;

if (!privateKey) {
  throw new Error("IMD_PRIVATE_KEY is required");
}

const signer = privateKeyToAccount(privateKey);
const client = createClient({ signer });

const quote = await client.quote("job.open", {
  objective: "Explain this repository",
  template: "single",
});

// Dry run by default: nothing is signed or paid. Set IMD_EXECUTE=1 only when you intend to pay.
const execute = process.env.IMD_EXECUTE === "1";

if (execute) {
  console.warn(
    `WARNING: IMD_EXECUTE=1 is set. Signing and submitting a real IMD payment for order ${quote.order.id}.`,
  );
}

const result = await client.pay(quote.order, signer, { execute });
console.log(result);
