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

// Omit execute for the safe dry run. Set it only when you intend to sign and submit payment.
const result = await client.pay(quote.order, signer, { execute: true });
console.log(result);
