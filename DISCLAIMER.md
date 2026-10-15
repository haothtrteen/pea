# Disclaimer

## Responsible use

PEA is built for lawful protection engineering: hardening, obfuscation planning and verification for software **you own or are explicitly authorized to test**. Intended uses include protecting your own licensing logic, raising the cost of reverse engineering your own products, security auditing of your own binaries, interoperability and preservation work, education, and coordinated vulnerability research on systems you are permitted to examine.

The PEA project does not support, and will not help with:

- circumventing DRM, license checks, anti-cheat systems or other technical protection measures — PEA's analysis domains exist to help you *build and verify* protections, not to defeat anyone else's;
- developing cheats, cracks, or tampering with online services or other people's software;
- bypassing authentication, bot protection or access controls on systems you are not authorized to test;
- copying proprietary software or reproducing its protected code and assets;
- evading the usage policies or safety measures of AI model providers;
- reselling or sharing AI accounts or API access.

You are responsible for obtaining any required authorization and for complying with applicable laws, license agreements and terms of service. Reverse engineering and software protection are regulated differently across jurisdictions; the legality of analyzing a given binary depends on who owns it and what you are permitted to do with it.

Requests for help with the uses above will be closed without response in issues and discussions.

## User responsibility

Do not use PEA for unauthorized access or exploitation, credential theft, malicious deployment of malware, unlawful collection or disclosure of data, unauthorized service disruption, or unlawful circumvention of access controls or licensing restrictions. Legitimate security research must remain within the rights and permissions applicable to the work.

You are responsible for your use of PEA, including the commands, configurations, plans and reports it produces, and any actions you or an agent you operate take based on them. Establish the legal authority and scope required for the targets, accounts, devices, software, data and operations involved.

## What PEA does not do

PEA is a planning and verification tool. Within the scope of this repository it:

- runs **read-only** analysis of a directory you explicitly authorize, and never executes your project's code;
- never connects to the network at runtime (the capability-intel connector is offline by default and requires an explicitly injected transport);
- never installs or executes third-party protection or reversing tools;
- never modifies your project — the executors (`apply_plan` / `verify_output` / `compare_results` / `rollback`) work on a PEA-managed workspace snapshot, and rollback discards or restores that workspace only. Executing them additionally requires an approval event from a trusted channel (your shell) plus a one-time token bound to the tool, plan digest, artifact digest, argument digest, tool version, authorized root and target path.

Protection strength claims must always be bound to a version, a sample, a test method, a coverage scope and the stated limitations. PEA does not promise absolute un-reverse-engineerability, and a tool crash, an unavailable provider or an empty output is never evidence of protection success.

## Third-party materials

References, catalogs and documentation about third-party projects (REA, ShellVMP, FDartVMP, blutter, reFlutter, Doldrums and others) describe those projects' publicly stated capabilities. They are research entries, not endorsements, and not proof that any capability has been verified locally. Third-party trademarks, project documentation, names, licenses and URLs remain owned by their respective holders. This license does not grant rights to third-party tools or code referenced by the documents.
