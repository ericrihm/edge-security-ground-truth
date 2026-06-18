# Your Brain on Vendor Selection: Seven Cognitive Biases That Distort Cybersecurity Decisions

You think you chose your firewall vendor based on data. You didn't. Here's what actually happened in your brain.

You sat in a boardroom. Someone pulled up a comparison chart. Numbers were cited. A decision was made. Everyone felt good about it. And nearly every step of that process was contaminated by cognitive biases so deeply embedded in human reasoning that even knowing about them barely helps.

This document uses real exploitation data from the [Edge Security Ground Truth](../README.md) dataset -- 115 CISA KEV-listed CVEs across 13 major edge vendors, 2020-2026 -- to show you exactly how your brain misleads you when you evaluate firewall, VPN, and edge-appliance vendors. Each bias is named, defined, demonstrated with real data, and followed by a question you can use to catch yourself doing it.

The goal is not to tell you which vendor to pick. It is to make you dangerous to your own worst instincts.

---

## 1. Anchoring Bias

**Definition:** The tendency to rely disproportionately on the first piece of information encountered (the "anchor") when making subsequent judgments, even when the anchor is arbitrary or misleading.

### The edge-security trap

Open any vendor comparison and the first number you see is the raw CVE count. Fortinet: 18. Check Point: 2. Your brain locks onto that 9:1 ratio before you have finished reading the sentence. From that moment forward, every subsequent fact is evaluated relative to that anchor.

But watch what happens when you look past the anchor.

Check Point's 2 KEV-listed CVEs are *both* confirmed zero-days -- a 100% zero-day rate. Fortinet's 7 zero-days out of 18 total gives them a 39% zero-day rate. Citrix has 7 zero-days out of 13 (54%). If your actual threat model is "how likely am I to be hit before a patch exists," the anchor steered you in the wrong direction. The vendor with the small, reassuring number has the highest proportion of vulnerabilities where no defense existed at the time of exploitation.

It gets worse. The statistical analysis shows that Fortinet's confidence interval ([10.66, 28.45]) fully contains the observed counts of 10 other vendors. The Poisson confidence intervals for 75 of 78 vendor pairs overlap. That clean "18 vs 2" your brain anchored on? It is one realization of a process with wide uncertainty bands. In a parallel universe with identical code quality, those numbers could easily be reversed.

### The psychological mechanism

Anchoring was first demonstrated by Tversky and Kahneman (1974) and has proven remarkably resistant to debiasing. Even experts in a domain -- people who should know better -- anchor on the first number they encounter. In a security context, the anchor is almost always the raw CVE count because it is the simplest, most available number. Everything that follows -- zero-day rates, time-to-exploit, CWE patterns, attribution -- gets insufficiently adjusted from that initial impression.

### Debiasing question

> *"If I had seen these vendors in reverse order -- Check Point first, Fortinet last -- would I reach the same conclusion?"*

---

## 2. Availability Heuristic

**Definition:** The tendency to estimate the likelihood of an event based on how easily examples come to mind, rather than on objective frequency. Vivid, recent, or emotionally charged events are overweighted; mundane or forgotten events are underweighted.

### The edge-security trap

Quick: which edge vendor had the worst security year recently?

If you said Fortinet (FortiBleed, the silent-patch controversy, CVE-2026-24858) or Ivanti (Emergency Directive 24-01, the CISA disconnect order), you are not analyzing data. You are recalling headlines. The availability heuristic has replaced your risk model with your news feed.

The base rate tells a different story. Every single one of the thirteen vendors in this dataset has had at least one mass-exploitation event. Citrix had CitrixBleed (CVE-2023-4966), weaponized by LockBit against Boeing, DP World, ICBC, and Allen & Overy. Cisco had ArcaneDoor -- state-sponsored zero-days implanting firmware-surviving backdoors on government firewalls. Palo Alto had CVE-2024-3400, a CVSS 10.0 unauthenticated RCE discovered already under active exploitation, 19 days before the hotfix. SonicWall had a cloud-backup breach that exposed firewall configurations for their entire cloud-backup customer base. Sophos documented a *five-year* nation-state campaign ("Pacific Rim") targeting their edge devices. Zyxel shipped a hardcoded plaintext credential (`zyfwp`) in a security appliance.

All of these are severe. Most of them you have already forgotten, because they were not the *last* headline you saw. The availability heuristic ensures that whichever vendor was in the news cycle at the moment you made your decision -- or at the moment your board asked the question -- dominates your assessment.

### The psychological mechanism

Availability is a substitution: your brain replaces the hard question ("what is the base rate of critical exploitation across vendors?") with an easier one ("which vendor name can I recall from a breach headline?"). Kahneman called this "What You See Is All There Is" (WYSIATI). In cybersecurity, where breach disclosures are staggered, unevenly covered, and quickly forgotten, WYSIATI is devastating. The vendor whose breach was six months ago feels safe. The vendor whose breach was last week feels dangerous. The data says they are statistically indistinguishable.

### Debiasing question

> *"Can I name a critical exploitation event for each of the vendors I am comparing -- not just the one I remember most recently?"*

---

## 3. Loss Aversion

**Definition:** Losses loom larger than equivalent gains. Kahneman and Tversky's prospect theory (1979) quantified this asymmetry with a loss-aversion coefficient of approximately lambda = 2.25: a $1 loss feels about 2.25 times as painful as a $1 gain feels good. Critically, people are risk-*seeking* in the domain of losses -- when all options look bad, they gamble.

### The edge-security trap

Consider a concrete scenario drawn from this dataset's base rates.

Your organization runs an internet-facing edge appliance. The data shows that 41% of exploited edge CVEs (47 of 115) are associated with ransomware campaigns. The median time-to-exploit for CVEs published since 2024 is 0 days -- exploitation is simultaneous with disclosure. Suppose a breach costs your organization $500,000 in incident response, downtime, and recovery.

Under expected value theory, the math is straightforward:

> Expected loss = 0.41 x $500,000 = **$205,000**

That is a clear signal to invest in rapid-patching infrastructure, assume-breach hunting, and management-plane isolation. But prospect theory says your brain does not process it that way. In the loss domain, the value function is concave -- you *underweight* the probability of the bad outcome because all options feel like losses, and losses trigger risk-seeking behavior:

> Prospect theory value ~ -$500,000^0.88 x 0.41^0.65 = roughly **-$86,000**

Your perceived risk is less than half the expected value. This is why CISOs gamble on "it won't happen to us" instead of investing $150,000 in a rapid-patching program that would be net-positive under any rational model. The loss domain makes the gamble feel less painful than the certain expenditure.

And here is the cruelest part: 41% of edge CVEs are weaponized within 7 days of disclosure. The median enterprise patch cycle for edge appliances is 30-60 days. You are not gambling on a coin flip. You are gambling on a coin that lands on "breach" four times out of ten, while your patching cadence structurally cannot respond in time.

### The psychological mechanism

Loss aversion interacts with the *certainty effect*: people overweight outcomes that are certain relative to those that are merely probable. Spending $150,000 on patching infrastructure is a *certain* loss. The breach is *probabilistic*. So the certain small loss feels worse than the probabilistic large loss, even when the expected values clearly favor the investment. This is compounded in cybersecurity by diffuse accountability -- if the breach happens, it is "the threat landscape." If the spend happens, it is on someone's budget.

### Debiasing question

> *"Am I rejecting this security investment because the threat is uncertain, or because the cost is certain -- and am I letting that asymmetry distort my judgment?"*

---

## 4. Framing Effect

**Definition:** The way information is presented (the "frame") systematically alters preferences and judgments, even when the underlying data is identical. Positive frames elicit different responses than negative frames for the same fact.

### The edge-security trap

Read these two statements:

> **Frame A:** "6 out of 115 CVEs across the dataset involve memory-safety bugs in Citrix products."

> **Frame B:** "Citrix has a 46% memory-safety concentration -- the highest of any vendor in the dataset."

Same data. Different reaction. Frame A makes 6 sound small against 115. Frame B makes 46% sound alarming. Neither is wrong. Both are incomplete. And whichever frame you encounter first will shape your evaluation of Citrix as a vendor.

Vendors and analysts exploit this constantly. Consider:

> **Frame C:** "Fortinet has 18 exploited edge CVEs -- the most of any vendor."

> **Frame D:** "Fortinet holds approximately 50% unit market share in firewalls and has 16.8% of exploited edge CVEs -- underrepresented relative to its installed base."

Frame C anchors you on the raw count. Frame D invokes Simpson's paradox: the vendor with the most CVEs may actually have a *lower per-device exploitation rate* than a vendor with 2 CVEs and a fraction of the installed base. Both frames are defensible readings of the data. The statistical analysis explicitly warns that without install-base normalization, raw counts "reward obscurity and penalize market leaders."

Or consider the zero-day framing:

> **Frame E:** "Only 33% of edge CVEs are zero-days."

> **Frame F:** "38 confirmed zero-days across 11 of 13 vendors -- one-third of everything on this list was exploited before any patch existed."

Frame E uses "only" and a percentage. Frame F uses "38 confirmed" and "one-third." The second frame produces urgency. The first produces complacency. The data is identical.

### The psychological mechanism

Framing effects are among the most robust findings in behavioral economics. They persist even when subjects are warned about them, even among experts, and even when the alternative frame is shown alongside. In vendor evaluation, framing is not accidental -- vendor marketing teams choose frames that minimize their exposure, and security journalists choose frames that maximize alarm. Neither serves your risk model.

### Debiasing question

> *"How would this same data point look if I deliberately reframed it -- as a percentage instead of a count, as a rate instead of a total, normalized per device instead of per vendor?"*

---

## 5. Sunk Cost Fallacy

**Definition:** The tendency to continue investing in a decision based on the cumulative prior investment ("sunk cost") rather than on the prospective value of continuing. Rational decision-making considers only future costs and benefits; sunk costs are irrelevant because they cannot be recovered.

### The edge-security trap

Your organization has invested $2 million in FortiGate infrastructure -- appliances, licensing, training, integration, playbooks, institutional knowledge. The data shows that Fortinet has 8 authentication/access-control CVEs out of 18 total (44%), the starkest auth-weakness concentration in the dataset. The analysis calls this "a pattern that suggests the auth subsystem in FortiOS lacks fundamental design-level guarantees." Eight authentication bypasses over seven years is not bad luck. It is an architectural signal.

But you are not going to rip out $2 million of infrastructure, are you?

That is the sunk cost fallacy at work. The $2 million is gone regardless of what you do next. The rational question is: "Given where we are today, what investment produces the best risk-adjusted outcome going forward?" Maybe the answer is still Fortinet -- with compensating controls, management-plane isolation, and a 24-hour patching SLA. Maybe it is a phased migration. The sunk cost fallacy prevents you from even asking the question, because the pain of "wasting" the prior investment is psychologically unbearable.

This plays out across the industry. Organizations that deployed Ivanti Connect Secure before the January 2024 zero-day chain -- the one that triggered CISA Emergency Directive 24-01, ordering federal agencies to *disconnect* their VPN appliances -- faced the same dilemma. CISA explicitly stated that factory resets might not remove persistence. The rational response was to treat the devices as compromised and rebuild. The sunk-cost response was to patch-and-pray, because replacing an entire VPN infrastructure mid-crisis is expensive and disruptive.

### The psychological mechanism

Sunk cost sensitivity is driven by loss aversion (Bias #3) applied to past investments. Abandoning the investment crystallizes the loss, making it real and emotionally painful. Continuing the investment keeps the loss "paper" -- theoretically recoverable. This is identical to the investor who holds a losing stock because selling would "lock in the loss." In cybersecurity, the stake is not money but organizational credibility: admitting the prior vendor decision was suboptimal feels like admitting a mistake, and organizations -- like individuals -- are strongly motivated to avoid that admission.

### Debiasing question

> *"If I were starting from scratch today, with zero existing infrastructure, would I make the same vendor choice -- and if not, what is the actual switching cost versus the risk of staying?"*

---

## 6. Optimism Bias

**Definition:** The tendency to believe that one is less likely to experience negative events than others, even when presented with base-rate information. Also called the "it won't happen to me" effect or unrealistic optimism.

### The edge-security trap

You just read that 41% of edge CVEs are associated with ransomware campaigns. You know that the median time-to-exploit for 2024 CVEs is 0 days. You know that 41% of all edge CVEs in this dataset were weaponized within 7 days of disclosure.

And you think: "That is bad, but my org patches faster than average."

Do you, though?

The data in this repository shows that 47 of 115 edge CVEs (40.9%) landed in KEV within 0-7 days of public disclosure. The typical enterprise patch cycle for network appliances is 30-60 days -- dominated by change-control processes, testing windows, and maintenance schedules. Even organizations with dedicated vulnerability management programs rarely achieve consistent sub-7-day patching for edge devices, because these appliances often require maintenance windows, firmware reboots, and validation of VPN/firewall rule continuity.

Optimism bias does not just affect patching speed. It distorts every layer of the assessment:

- "41% ransomware association sounds bad, but we have good backups." (Do your backups cover the firewall configs that a SonicWall-style cloud breach would expose?)
- "Zero-days are a nation-state problem, not a mid-market problem." (47 of 115 CVEs are ransomware-associated. Ransomware operators do not check your org size before deploying.)
- "We have compensating controls." (The ArcaneDoor implants on Cisco ASA firewalls survived reboots and persisted in firmware. Your compensating controls assumed a software-layer adversary.)

The dataset's conclusion is blunt: "No major edge vendor is meaningfully safer than the others." Optimism bias is the mechanism by which you read that sentence, agree with it in the abstract, and then exempt your own deployment from it.

### The psychological mechanism

Optimism bias is one of the most robust cognitive biases, documented across cultures, age groups, and expertise levels. Weinstein (1980) showed that people consistently rate their own risk as below average for negative events, even in domains where they have no informational advantage. In cybersecurity, optimism bias is reinforced by *survivorship* -- every day you are not breached feels like evidence that your defenses work, rather than evidence that you have not yet been targeted. The absence of a negative outcome is misinterpreted as the presence of a positive one.

### Debiasing question

> *"What is my actual mean-time-to-patch for edge appliances over the last 12 months -- not the SLA, not the target, but the measured reality -- and how does it compare to the 7-day weaponization window in this data?"*

---

## 7. Survivorship Bias

**Definition:** The logical error of concentrating on entities that "survived" a selection process while overlooking those that did not, leading to false conclusions about what drives success or failure. In security: focusing on the vendors that *appear* in breach data while ignoring the reasons some vendors do not appear.

### The edge-security trap

Check Point has 2 exploited edge CVEs. Zyxel has 6. This might tempt you to conclude that Check Point's code is three times more secure than Zyxel's. But you are looking at the survivors -- the vulnerabilities that were found, reported, assigned a CVE, confirmed as exploited, and added to the CISA KEV catalog. At every step of that pipeline, there is selection bias.

The statistical analysis in this dataset warns explicitly: "Vendors that are more widely deployed, more transparent in disclosure, and more prominent in breach news will accumulate more KEV entries independent of code quality. This is a form of detection bias or surveillance bias analogous to the well-known problem in epidemiology where diseases screened more frequently appear more prevalent." With 13 vendors and counts ranging 2–18, 96% of vendor-pair confidence intervals overlap — meaning the observed ranking is mostly noise.

Consider the chain:
1. **Researcher attention** is not evenly distributed. Fortinet and Palo Alto, with the largest install bases, attract the most security researchers. More researchers means more bugs found. More bugs found means more CVEs. More CVEs means more KEV entries. None of this requires that the code be worse.
2. **Disclosure transparency** varies. Zyxel silently patched CVE-2022-30525 -- firmware released without a CVE or advisory, discovered only when Rapid7 diffed the update. How many other silent patches exist across vendors, never discovered, never counted?
3. **Exploitation visibility** is uneven. A vulnerability exploited against a Fortune 500 company running Palo Alto gets an incident report, a Mandiant analysis, and a CISA KEV entry. The same class of vulnerability exploited against a small business running a lesser-known vendor's appliance goes unreported and uncounted.

The vendors you *don't* hear about are not necessarily safer. They may simply be less scrutinized. Zyxel's SMB customer base -- smaller IT teams, less security monitoring, fewer incident reports -- means exploitation events are less likely to be detected, reported, and cataloged. This is not security through quality. It is obscurity through neglect.

The dataset makes this explicit: Check Point's low count "partly reflects fewer disclosed edge vulnerabilities but also lower installed base and researcher attention -- it does not mean Check Point is safe."

### The psychological mechanism

Survivorship bias was famously illustrated by Abraham Wald's WWII bomber analysis: the military wanted to armor the parts of returning planes that showed bullet holes. Wald pointed out that the holes showed where planes could take damage and *survive* -- the planes that took damage elsewhere never came back. In vendor evaluation, the "bullet holes" are the CVEs that made it into public catalogs. The vendors with fewer holes may be the ones whose vulnerabilities never made it back for analysis -- not the ones that are built better.

### Debiasing question

> *"Is this vendor's low CVE count evidence of better security engineering, or evidence of less researcher scrutiny and a smaller installed base generating fewer incident reports?"*

---

## Decision Hygiene Checklist

Before you select or renew an edge-security vendor, ask these five questions. Write down the answers. If you cannot answer them with data, you are operating on bias.

### 1. What is my actual patching speed, and does it fit inside the threat window?

Measure your real mean-time-to-patch for edge appliances over the past 12 months. Compare it to the dataset's finding: 41% of edge CVEs are weaponized within 7 days. If your MTTP exceeds 7 days, no vendor choice compensates -- you are structurally exposed regardless of which name is on the box.

### 2. Am I comparing per-device risk or per-vendor headlines?

Raw CVE counts penalize market leaders and reward obscurity. Before comparing vendors, ask whether the count difference is explained by installed base, researcher attention, or disclosure practices. The statistical analysis shows that 96% of vendor-pair confidence intervals overlap -- meaning the observed ranking is likely noise, not signal.

### 3. What is this vendor's weakness fingerprint, and does it match my threat model?

Each vendor has a distinct CWE concentration. Fortinet skews auth bypass (44%). Ivanti skews injection (46%). Cisco and Citrix concentrate in memory safety. A vendor's weakness fingerprint tells you what class of bug is most likely to appear next. Match that against your specific deployment: is the management plane exposed? Are you running SSL-VPN? Is the device in a segment where memory corruption enables lateral movement?

### 4. Am I evaluating the vendor's response posture, not just their vulnerability count?

Two vendors can have identical CVE counts and wildly different risk profiles based on how they respond. Did the vendor silently patch (Fortinet CVE-2023-27997, Zyxel CVE-2022-30525) or disclose proactively with indicators of compromise (Cisco's ArcaneDoor coordination, Sophos's Pacific Rim transparency)? A vendor that discloses quickly and provides detection guidance is operationally safer than a vendor with fewer CVEs but a pattern of silent fixes.

### 5. What would change my mind?

Write down the specific evidence that would cause you to switch vendors or to stay. If you cannot articulate what would change your decision, the decision is not based on data -- it is based on comfort, familiarity, and sunk costs. The most dangerous bias is the one you refuse to name.

---

## A Note on Humility

Every bias in this document applies to the authors of this dataset too. We anchored on CISA KEV as the gating framework. We were subject to availability when selecting which vendor narratives to emphasize. We framed data in ways that shaped your reaction. The difference between a biased analysis and a rigorous one is not the absence of bias -- it is the presence of transparency about where bias lives.

The dataset publishes its scope rules, its scripts, its limitations, and its confidence intervals. It explicitly states that the vendor ranking "is a sort, not a verdict." It warns that installed base is uncontrolled and cannot be normalized away. It tells you that 96% of vendor-pair comparisons are statistically indistinguishable.

The data does not tell you which vendor to choose. It tells you that the question itself -- "which vendor is safest?" -- is malformed. The better question is: "Given that all edge vendors are actively targeted, and exploitation timelines have compressed to zero, what response posture minimizes my risk regardless of which name is on the appliance?"

That question is harder. It is also the right one.

---

*Based on data from the [Edge Security Ground Truth](https://github.com/ericrihm/edge-security-ground-truth) repository: 115 CISA KEV-listed CVEs, 13 vendors, 2020-2026. All statistics reproducible via the scripts in `scripts/`. See [STATISTICS.md](STATISTICS.md), [TIME-TO-EXPLOIT.md](TIME-TO-EXPLOIT.md), [CWE-ANALYSIS.md](CWE-ANALYSIS.md), and [EXECUTIVE-SUMMARY.md](EXECUTIVE-SUMMARY.md) for underlying analyses.*
