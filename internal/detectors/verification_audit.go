package detectors

type VerificationAuditStatus string

const (
	VerificationAuditReviewed          VerificationAuditStatus = "reviewed"
	VerificationAuditRequiresHardening VerificationAuditStatus = "requires_hardening"
	VerificationAuditBlocked           VerificationAuditStatus = "blocked"
	VerificationAuditPending           VerificationAuditStatus = "pending_review"
	VerificationAuditNoVerifier        VerificationAuditStatus = "no_verifier"
)

type VerificationAuditEntry struct {
	ID                 string                  `json:"id"`
	Name               string                  `json:"name"`
	Verifiable         bool                    `json:"verifiable"`
	VerificationSafety VerificationSafety      `json:"verification_safety,omitempty"`
	AuditStatus        VerificationAuditStatus `json:"audit_status"`
	AuditBatch         int                     `json:"audit_batch,omitempty"`
	Notes              string                  `json:"notes,omitempty"`
}

type VerificationAuditReport struct {
	Total             int                      `json:"total"`
	Reviewed          int                      `json:"reviewed"`
	RequiresHardening int                      `json:"requires_hardening"`
	Blocked           int                      `json:"blocked"`
	PendingReview     int                      `json:"pending_review"`
	NoVerifier        int                      `json:"no_verifier"`
	Entries           []VerificationAuditEntry `json:"entries"`
}

type verificationAuditAssessment struct {
	Status VerificationAuditStatus
	Batch  int
	Notes  string
}

var verificationAuditAssessments = map[string]verificationAuditAssessment{
	"google-api-key":    {Status: VerificationAuditBlocked, Batch: 1, Notes: "Generic Google keys cannot be validated reliably against a single provider API."},
	"ngrok-token":       {Status: VerificationAuditBlocked, Batch: 1, Notes: "Detected credential families do not share a proven verification contract."},
	"langsmith-api-key": {Status: VerificationAuditBlocked, Batch: 1, Notes: "Cloud region, service-key tenant context, and self-hosted endpoint context are unresolved."},

	"openai-key":                {Status: VerificationAuditRequiresHardening, Batch: 1, Notes: "Tighten supported key variants and require a list-shaped model response."},
	"pagerduty-token":           {Status: VerificationAuditRequiresHardening, Batch: 1, Notes: "Split REST tokens from routing and integration keys before promotion."},
	"buildkite-token":           {Status: VerificationAuditRequiresHardening, Batch: 1, Notes: "Route API, portal, and cluster-agent token variants independently."},
	"square-token":              {Status: VerificationAuditRequiresHardening, Batch: 1, Notes: "Preserve local rejection of application secrets and validate merchant response structure."},
	"discord-webhook":           {Status: VerificationAuditReviewed, Batch: 1, Notes: "Webhook metadata identity is schema-validated and suppressed."},
	"grafana-token":             {Status: VerificationAuditRequiresHardening, Batch: 1, Notes: "Grafana Cloud region context is incomplete."},
	"honeycomb-api-key":         {Status: VerificationAuditRequiresHardening, Batch: 1, Notes: "Split key formats and correlate US or EU endpoint context."},
	"opsgenie-api-key":          {Status: VerificationAuditRequiresHardening, Batch: 1, Notes: "Correlate global or EU endpoint context and harden restricted-key classification."},
	"webex-bot-token":           {Status: VerificationAuditReviewed, Batch: 1, Notes: "Bot identity fields are schema-validated and suppressed."},
	"huggingface-token":         {Status: VerificationAuditRequiresHardening, Batch: 1, Notes: "Reconcile supported token formats and validate whoami response structure."},
	"groq-api-key":              {Status: VerificationAuditReviewed, Batch: 1, Notes: "OpenAI-compatible model-list response is schema-validated."},
	"replicate-token":           {Status: VerificationAuditRequiresHardening, Batch: 1, Notes: "Confirm current token length and validate account identity fields."},
	"airtable-pat":              {Status: VerificationAuditReviewed, Batch: 1, Notes: "Whoami identity is schema-validated and suppressed."},
	"asana-pat":                 {Status: VerificationAuditReviewed, Batch: 1, Notes: "Current-user data.gid is schema-validated and suppressed."},
	"clickup-token":             {Status: VerificationAuditReviewed, Batch: 1, Notes: "Current-user identity is schema-validated and suppressed."},
	"typeform-token":            {Status: VerificationAuditRequiresHardening, Batch: 1, Notes: "Preserve structured authentication errors and validate user identity."},
	"hubspot-private-app-token": {Status: VerificationAuditRequiresHardening, Batch: 1, Notes: "Validate usage response and distinguish structured scope failures."},
	"mailchimp-key":             {Status: VerificationAuditRequiresHardening, Batch: 1, Notes: "Validate data-center suffix and ping response."},
	"klaviyo-key":               {Status: VerificationAuditRequiresHardening, Batch: 1, Notes: "Replace profile lookup with bounded account metadata."},
	"iterable-api-key":          {Status: VerificationAuditRequiresHardening, Batch: 1, Notes: "Resolve key type and region ambiguity before classifying rejection."},
	"nightfall-api-key":         {Status: VerificationAuditReviewed, Batch: 1, Notes: "Read-only detection-rules collection is validated and suppressed."},
	"pinecone-api-key":          {Status: VerificationAuditReviewed, Batch: 1, Notes: "Control-plane index collection is schema-validated and suppressed."},
	"elevenlabs-api-key":        {Status: VerificationAuditReviewed, Batch: 1, Notes: "User identity response is schema-validated and suppressed."},
	"xai-api-key":               {Status: VerificationAuditRequiresHardening, Batch: 1, Notes: "Switch to the documented API-key identity endpoint."},
	"cohere-api-key":            {Status: VerificationAuditReviewed, Batch: 1, Notes: "Model-list response is schema-validated; context-sensitive rejection remains unknown."},
	"mistral-api-key":           {Status: VerificationAuditReviewed, Batch: 1, Notes: "Model-list response is schema-validated; hosted-key rejection remains unknown."},
	"togetherai-api-key":        {Status: VerificationAuditReviewed, Batch: 1, Notes: "Top-level model-list response is schema-validated and suppressed."},
	"fireworksai-api-key":       {Status: VerificationAuditReviewed, Batch: 1, Notes: "Bounded model response is schema-validated and suppressed."},
	"voyageai-api-key":          {Status: VerificationAuditRequiresHardening, Batch: 1, Notes: "Validate bounded file-list response and suppress metadata."},
	"perplexity-api-key":        {Status: VerificationAuditReviewed, Batch: 1, Notes: "Router model-list response is schema-validated and suppressed."},
	"openrouter-api-key":        {Status: VerificationAuditReviewed, Batch: 1, Notes: "Uses the documented key endpoint with nested data validation."},
	"ai21-api-key":              {Status: VerificationAuditRequiresHardening, Batch: 1, Notes: "Validate file-list response and distinguish malformed requests."},
	"cerebras-api-key":          {Status: VerificationAuditReviewed, Batch: 1, Notes: "Model-list response is schema-validated and forbidden responses remain ambiguous."},
	"baseten-api-key":           {Status: VerificationAuditReviewed, Batch: 1, Notes: "Uses bearer management authentication with model-list validation."},
	"runpod-api-key":            {Status: VerificationAuditRequiresHardening, Batch: 1, Notes: "Move to the documented REST v1 pods endpoint."},
	"fal-ai-api-key":            {Status: VerificationAuditRequiresHardening, Batch: 1, Notes: "Prove authenticated model-list semantics and validate key boundaries."},
	"novita-api-key":            {Status: VerificationAuditRequiresHardening, Batch: 1, Notes: "Replace the public model list with the authenticated balance endpoint."},
	"zilliz-api-key":            {Status: VerificationAuditRequiresHardening, Batch: 1, Notes: "Preserve application-code classification and suppress project data."},
	"chroma-cloud-api-key":      {Status: VerificationAuditRequiresHardening, Batch: 1, Notes: "Validate cloud identity fields and region fallback."},
	"harness-pat":               {Status: VerificationAuditRequiresHardening, Batch: 1, Notes: "Validate SaaS current-user response while preserving self-managed ambiguity."},
	"zoho-crm-token":            {Status: VerificationAuditRequiresHardening, Batch: 1, Notes: "Validate user response and bounded regional fallback."},
	"intercom-access-token":     {Status: VerificationAuditRequiresHardening, Batch: 1, Notes: "Validate me response and supported token encoding."},
	"front-api-token":           {Status: VerificationAuditRequiresHardening, Batch: 1, Notes: "Narrow token variants and validate me response."},
	"segment-api-key":           {Status: VerificationAuditRequiresHardening, Batch: 1, Notes: "Validate workspace collection response and suppress metadata."},
	"posthog-personal-api-key":  {Status: VerificationAuditRequiresHardening, Batch: 1, Notes: "Validate user identity and preserve self-hosted endpoint ambiguity."},
	"launchdarkly-key":          {Status: VerificationAuditRequiresHardening, Batch: 1, Notes: "Validate caller identity and preserve local rejection of SDK keys."},
	"postmark-token":            {Status: VerificationAuditRequiresHardening, Batch: 1, Notes: "Route server and account token variants independently."},

	"coda-api-token":                     {Status: VerificationAuditRequiresHardening, Batch: 2, Notes: "Validate whoami identity and suppress response metadata."},
	"calendly-api-key":                   {Status: VerificationAuditRequiresHardening, Batch: 2, Notes: "Validate resource identity and realistic JWT boundaries."},
	"monday-api-token":                   {Status: VerificationAuditRequiresHardening, Batch: 2, Notes: "Suppress GraphQL identity response and harden error classification."},
	"flyio-token":                        {Status: VerificationAuditRequiresHardening, Batch: 2, Notes: "Validate authentication response before auth-only promotion."},
	"cloudflare-ca-key":                  {Status: VerificationAuditBlocked, Batch: 2, Notes: "Cloudflare Origin CA service keys retire on 2026-09-30."},
	"azure-app-config-connection-string": {Status: VerificationAuditReviewed, Batch: 2, Notes: "Signed read-only App Configuration request is context-complete and suppressed."},
	"azure-storage-connection-string":    {Status: VerificationAuditReviewed, Batch: 2, Notes: "Signed bounded Azure Storage list request is context-complete and suppressed."},
	"spectralops-token":                  {Status: VerificationAuditReviewed, Batch: 2, Notes: "Read-only user collection contract is bounded and suppressed."},
	"atlassian-api-token":                {Status: VerificationAuditRequiresHardening, Batch: 2, Notes: "Validate organization collection and suppress metadata."},
	"salesforce-access-token":            {Status: VerificationAuditRequiresHardening, Batch: 2, Notes: "Validate userinfo and preserve production or sandbox endpoint ambiguity."},
	"openphone-api-key":                  {Status: VerificationAuditRequiresHardening, Batch: 2, Notes: "Validate bounded users response and provider rename contract."},
	"dialpad-api-key":                    {Status: VerificationAuditRequiresHardening, Batch: 2, Notes: "Validate company identity and preserve restricted-key ambiguity."},
	"ringover-api-key":                   {Status: VerificationAuditReviewed, Batch: 2, Notes: "Read-only user collection is schema-classified and suppressed."},
	"callrail-api-key":                   {Status: VerificationAuditRequiresHardening, Batch: 2, Notes: "Validate bounded accounts response and suppress metadata."},
	"mailjet-basic-auth":                 {Status: VerificationAuditReviewed, Batch: 2, Notes: "Credential parsing and bounded message request are validated and suppressed."},
	"urlscan-api-key":                    {Status: VerificationAuditRequiresHardening, Batch: 2, Notes: "Validate quota response and suppress account details."},
	"deepseek-api-key":                   {Status: VerificationAuditRequiresHardening, Batch: 2, Notes: "Validate model-list response and suppress provider errors."},
	"weightsandbiases-api-key":           {Status: VerificationAuditRequiresHardening, Batch: 2, Notes: "Suppress GraphQL identity and preserve self-hosted ambiguity."},
	"assemblyai-api-key":                 {Status: VerificationAuditRequiresHardening, Batch: 2, Notes: "Validate bounded transcript collection and regional fallback."},
	"deepgram-api-key":                   {Status: VerificationAuditRequiresHardening, Batch: 2, Notes: "Validate projects response and suppress metadata."},
	"contentful-pat":                     {Status: VerificationAuditRequiresHardening, Batch: 2, Notes: "Validate bounded spaces response and regional fallback."},
	"storyblok-personal-access-token":    {Status: VerificationAuditRequiresHardening, Batch: 2, Notes: "Validate bounded spaces response across management regions."},
	"storyblok-access-token":             {Status: VerificationAuditRequiresHardening, Batch: 2, Notes: "Validate current-space response across CDN regions."},
	"sanity-auth-token":                  {Status: VerificationAuditRequiresHardening, Batch: 2, Notes: "Resolve personal and robot token endpoint compatibility."},
	"datocms-api-token":                  {Status: VerificationAuditRequiresHardening, Batch: 2, Notes: "Validate JSON API site identity and suppress metadata."},
	"elastic-email-api-key":              {Status: VerificationAuditRequiresHardening, Batch: 2, Notes: "Replace sensitive key listing with bounded account identity."},
	"webflow-api-key":                    {Status: VerificationAuditRequiresHardening, Batch: 2, Notes: "Move to documented token introspection and validate identity."},
	"mapbox-secret-token":                {Status: VerificationAuditRequiresHardening, Batch: 2, Notes: "Validate token inspection response and suppress authorization metadata."},
	"locationiq-api-key":                 {Status: VerificationAuditRequiresHardening, Batch: 2, Notes: "Validate balance response and regional fallback."},
	"coinapi-key":                        {Status: VerificationAuditRequiresHardening, Batch: 2, Notes: "Validate limits response and suppress quota metadata."},
	"onfido-api-token":                   {Status: VerificationAuditRequiresHardening, Batch: 2, Notes: "Validate bounded applicant collection and suppress PII."},
	"unit-api-token":                     {Status: VerificationAuditReviewed, Batch: 2, Notes: "Bounded account collection is schema-classified and suppressed."},
	"increase-api-key":                   {Status: VerificationAuditRequiresHardening, Batch: 2, Notes: "Split API credentials from webhook and OAuth secrets."},
	"lithic-api-key":                     {Status: VerificationAuditReviewed, Batch: 2, Notes: "Bounded account-holder collection is schema-classified and suppressed."},
	"persona-api-key":                    {Status: VerificationAuditRequiresHardening, Batch: 2, Notes: "Split API tokens from webhook secrets and suppress inquiry PII."},
	"apisports-api-key":                  {Status: VerificationAuditRequiresHardening, Batch: 2, Notes: "Suppress subscription response and narrow invalid markers."},
	"opticodds-api-key":                  {Status: VerificationAuditReviewed, Batch: 2, Notes: "Static sports collection is schema-classified and suppressed."},
	"complyadvantage-api-key":            {Status: VerificationAuditRequiresHardening, Batch: 2, Notes: "Replace unbounded regional user lists with a bounded contract."},
	"bitgo-access-token":                 {Status: VerificationAuditRequiresHardening, Batch: 2, Notes: "Confirm test host and validate user identity."},
	"circle-api-key":                     {Status: VerificationAuditRequiresHardening, Batch: 2, Notes: "Split API keys from webhook secrets and support sandbox context."},
	"trulioo-api-key":                    {Status: VerificationAuditReviewed, Batch: 2, Notes: "Dedicated authentication endpoint is schema-classified and suppressed."},
	"etherscan-api-key":                  {Status: VerificationAuditRequiresHardening, Batch: 2, Notes: "Suppress quota-bearing chain response and test provider error codes."},
	"guardian-api-key":                   {Status: VerificationAuditRequiresHardening, Batch: 2, Notes: "Validate bounded search response and suppress article metadata."},
	"sourcegraph-token":                  {Status: VerificationAuditRequiresHardening, Batch: 2, Notes: "Suppress cloud identity and preserve local token no-request behavior."},
	"sourcegraph-cody-token":             {Status: VerificationAuditRequiresHardening, Batch: 2, Notes: "Validate limits response and preserve forbidden ambiguity."},
	"snyk-api-key":                       {Status: VerificationAuditRequiresHardening, Batch: 2, Notes: "Validate regional self response and cap fallback requests."},
	"uptimerobot-api-key":                {Status: VerificationAuditRequiresHardening, Batch: 2, Notes: "Suppress bounded monitor response and test application errors."},
	"statuspage-api-key":                 {Status: VerificationAuditRequiresHardening, Batch: 2, Notes: "Bound or replace page collection and confirm authorization form."},
	"sendinblue-api-key":                 {Status: VerificationAuditRequiresHardening, Batch: 2, Notes: "Validate account identity and suppress plan and address data."},
	"teamwork-token":                     {Status: VerificationAuditReviewed, Batch: 2, Notes: "Launchpad identity response is schema-classified and suppressed."},
}

func buildVerificationAuditReport(ds []Detector) VerificationAuditReport {
	infos := RegistryInfo(ds)
	report := VerificationAuditReport{Total: len(infos), Entries: make([]VerificationAuditEntry, 0, len(infos))}
	for _, info := range infos {
		entry := VerificationAuditEntry{ID: info.ID, Name: info.Name, Verifiable: info.Verifiable, VerificationSafety: info.VerificationSafety}
		assessment, assessed := verificationAuditAssessments[info.ID]
		switch {
		case !info.Verifiable:
			entry.AuditStatus = VerificationAuditNoVerifier
			report.NoVerifier++
		case info.VerificationSafety != VerificationSafetyUnreviewed:
			entry.AuditStatus = VerificationAuditReviewed
			if assessed {
				entry.AuditBatch = assessment.Batch
				entry.Notes = assessment.Notes
			}
			report.Reviewed++
		default:
			if !assessed {
				entry.AuditStatus = VerificationAuditPending
				report.PendingReview++
				break
			}
			entry.AuditStatus = assessment.Status
			entry.AuditBatch = assessment.Batch
			entry.Notes = assessment.Notes
			switch assessment.Status {
			case VerificationAuditRequiresHardening:
				report.RequiresHardening++
			case VerificationAuditBlocked:
				report.Blocked++
			default:
				report.PendingReview++
			}
		}
		report.Entries = append(report.Entries, entry)
	}
	return report
}
