export type SampleEmail = {
  id: string;
  label: string;
  category: "phishing" | "safe";
  body: string;
};

export const SAMPLE_EMAILS: SampleEmail[] = [
  {
    id: "ph-credential",
    label: "[PHISHING] Microsoft 365 password reset",
    category: "phishing",
    body: `From: Microsoft Security <no-reply@micr0soft-support.com>
Subject: URGENT: Your Microsoft 365 password expires in 24 hours

Dear User,

Our records indicate that your Microsoft 365 password will expire within 24 hours.
Failure to verify your account immediately will result in permanent suspension.

Please confirm your credentials here:
http://login-microsoftonline.verify-account-secure.ru/auth

Thank you,
Microsoft Account Team`,
  },
  {
    id: "ph-ceo",
    label: "[PHISHING] CEO urgent wire transfer",
    category: "phishing",
    body: `From: John Carter (CEO) <j.carter.ceo@gmail.com>
Subject: Need this done quickly - confidential

Hi,

Are you at your desk? I need you to process an urgent wire transfer to a new vendor
before end of day. This is highly confidential - do not discuss with anyone in the office.
Reply ASAP with your direct number.

Sent from my iPhone`,
  },
  {
    id: "ph-package",
    label: "[PHISHING] DHL package delivery failed",
    category: "phishing",
    body: `From: DHL Express <delivery@dhl-tracking-update.info>
Subject: Action required: Your package #DHL8821 could not be delivered

Your shipment is being held due to unpaid customs fees ($2.99).
Please verify your address and pay the outstanding fee within 12 hours
or your package will be returned to sender.

Click here to pay: http://192.168.45.10/dhl-customs/pay`,
  },
  {
    id: "ph-bank",
    label: "[PHISHING] Bank account verification",
    category: "phishing",
    body: `From: Chase Online <secure@chase-verify-now.co>
Subject: Unusual sign-in activity detected

We detected a sign-in to your account from a new device in Lagos, Nigeria.
If this was not you, verify your identity immediately by entering your
account number, SSN, and online banking password at the link below.

https://chase-verify-now.co/secure/login`,
  },
  {
    id: "ph-crypto",
    label: "[PHISHING] Crypto wallet airdrop",
    category: "phishing",
    body: `Subject: You qualified for a 2.5 ETH airdrop!

Congratulations! Your wallet was selected to claim 2.5 ETH from the Uniswap loyalty program.
Connect your wallet and enter your seed phrase to verify ownership:

http://uniswap-airdrop-claim.xyz/connect

Offer expires in 1 hour.`,
  },
  {
    id: "ph-it",
    label: "[PHISHING] IT helpdesk mailbox quota",
    category: "phishing",
    body: `From: IT Helpdesk <helpdesk@company-it-support.tk>
Subject: Mailbox storage 99% full - emails will be blocked

Your mailbox has reached 99% capacity. To avoid losing incoming emails,
please re-validate your account within the next hour.

Validate here: http://owa-mail-validate.company-it-support.tk/login

- IT Helpdesk`,
  },
  {
    id: "safe-newsletter",
    label: "[SAFE] GitHub newsletter",
    category: "safe",
    body: `From: GitHub <noreply@github.com>
Subject: The ReadME Project - November highlights

Hi there,

This month on the ReadME Project we feature interviews with maintainers of
popular open-source security tooling, plus highlights from GitHub Universe.

Read the latest stories: https://github.com/readme

You are receiving this email because you subscribed to GitHub updates.
Unsubscribe: https://github.com/settings/emails`,
  },
  {
    id: "safe-calendar",
    label: "[SAFE] Calendar invite from colleague",
    category: "safe",
    body: `From: Sarah Lee <sarah.lee@company.com>
Subject: Invitation: Thesis defense rehearsal @ Tue Apr 30, 2:00 PM

Hi team,

I've scheduled a 45-minute rehearsal for the thesis defense on Tuesday at 2:00 PM
in Room 305. Please accept or decline the invite at your convenience.

Best,
Sarah`,
  },
  {
    id: "safe-hr",
    label: "[SAFE] Internal HR memo",
    category: "safe",
    body: `From: HR Department <hr@company.com>
Subject: Updated remote-work policy - effective May 1

Dear colleagues,

Please find attached the updated remote-work policy, which takes effect on May 1.
Key changes are summarized in section 2 of the document. If you have questions,
reach out to your manager or to hr@company.com.

Thank you,
Human Resources`,
  },
  {
    id: "safe-receipt",
    label: "[SAFE] Online order receipt",
    category: "safe",
    body: `From: orders@bookstore.com
Subject: Your order #A-78213 has shipped

Thanks for your order! Your package shipped today via standard mail and
should arrive within 3-5 business days.

Tracking: https://bookstore.com/orders/A-78213

No action is required.`,
  },
];
