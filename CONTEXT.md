# SmokedMeat

SmokedMeat models an authorized CI/CD red-team engagement as a progression from analysis through initial access, post-exploitation, and pivots. Its language distinguishes delivery mechanisms, resulting execution, and collected evidence.

## Engagement

**Operator**:
A person conducting an authorized engagement through SmokedMeat.
_Avoid_: User, client

**Target**:
The GitHub organization or repository currently in scope for analysis and operator actions.
_Avoid_: Goal, victim

**Session**:
An engagement-scoped grouping of operators, agents, activity, and collected evidence for a target.
_Avoid_: Connection, callback, shell session

**Recon**:
Collection and classification of the CI environment, runner context, credentials, and available identity providers.
_Avoid_: Analysis, scan

**Analysis**:
Static examination of repositories and CI workflows that produces findings without requiring code execution on a runner.
_Avoid_: Recon, exploit

**Secret detection**:
Static Analysis that identifies credential material in target repositories without depending on a particular detection engine.
_Avoid_: Gitleaks scan, secret scan

**Finding**:
Evidence of a CI/CD weakness produced by analysis before it is normalized for operator use.
_Avoid_: Issue, ticket

**Vulnerability**:
The engagement-tracked representation of a finding, including its affected workflow context and exploit-support status. A vulnerability may be exploit-supported or analyze-only.
_Avoid_: GitHub issue

**Analyze-only**:
A vulnerability that SmokedMeat can explain and track but cannot currently exploit through an honest supported path.
_Avoid_: Unsupported vulnerability

**Exploit**:
An authorized attempt to turn a vulnerability into execution or access in the target CI/CD environment.
_Avoid_: Analysis, delivery

**Delivery method**:
The route used to place or trigger a stager, such as a pull request, issue, comment, workflow dispatch, or LOTP payload.
_Avoid_: Exploit class

## Execution And Access

**Stager**:
The initial payload delivered through a vulnerable workflow that contacts Kitchen and starts Brisket.
_Avoid_: Agent, beacon

**Callback**:
A recorded invocation of a registered stager, correlated with its deployment and any resulting agent.
_Avoid_: Beacon, session

**Brisket**:
The SmokedMeat implant that runs in a compromised CI runner.
_Avoid_: Agent when referring to a running instance

**Agent**:
A running Brisket instance with its own identity and runner context that can report status and receive orders.
_Avoid_: Stager, callback

**Beacon**:
A liveness and status signal sent by an agent to Kitchen.
_Avoid_: Callback, coleslaw

**Order**:
A command directed to one agent as part of an operator session.
_Avoid_: Task, request

**Coleslaw**:
An agent's response to one order, including its output, error, and completion status.
_Avoid_: Beacon, callback

**Express mode**:
A callback mode for immediate collection without retaining a commandable agent.
_Avoid_: Dwell, resident

**Dwell mode**:
A callback mode that keeps an agent commandable for a bounded period.
_Avoid_: Express, resident

**Resident foothold**:
A persistent self-hosted runner foothold that can observe later jobs and re-establish agent access.
_Avoid_: Dwell session, callback

**Loot**:
Credentials, secrets, keys, tokens, and other access material collected during an engagement.
_Avoid_: Finding

**Pivot**:
Use of collected access to reach additional repositories, identities, cloud resources, or execution paths.
_Avoid_: Recon, exploit

## Attack Model

**Pantry**:
The persistent attack graph representing discovered entities, their state, and the paths between them.
_Avoid_: Tree, inventory

**Analysis ingestion**:
Reconciliation of completed Analysis evidence into Pantry within the repositories the Analysis covered, while preserving evidence collected through other engagement activity.
_Avoid_: Pantry import, graph import

**Asset**:
A tracked entity in Pantry, such as an organization, repository, workflow, job, vulnerability, credential, cloud resource, or agent.
_Avoid_: Finding, row

**Relationship**:
A directed connection between two Pantry assets that records how access, discovery, or execution can flow.
_Avoid_: Reference, association

**Attack path**:
An ordered route through assets and relationships from an initial weakness toward execution, loot, or a pivot.
_Avoid_: Workflow, kill command

**Known entity**:
An organization or repository already observed in the engagement, retained so later pivots can distinguish new discoveries.
_Avoid_: Asset

**LOTP**:
Living Off The Pipeline, a delivery technique that uses build or package configuration executed by a CI workflow.
_Avoid_: Package-manager exploit

## Product Roles

**Counter**:
The operator-facing SmokedMeat client used to conduct an engagement.
_Avoid_: Kitchen, agent

**Kitchen**:
The SmokedMeat teamserver that coordinates operators, stagers, callbacks, agents, and persistent engagement state.
_Avoid_: Counter, implant
