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
	"discord-webhook":           {Status: VerificationAuditRequiresHardening, Batch: 1, Notes: "Validate webhook metadata response and suppress guild and channel details."},
	"grafana-token":             {Status: VerificationAuditRequiresHardening, Batch: 1, Notes: "Grafana Cloud region context is incomplete."},
	"honeycomb-api-key":         {Status: VerificationAuditRequiresHardening, Batch: 1, Notes: "Split key formats and correlate US or EU endpoint context."},
	"opsgenie-api-key":          {Status: VerificationAuditRequiresHardening, Batch: 1, Notes: "Correlate global or EU endpoint context and harden restricted-key classification."},
	"webex-bot-token":           {Status: VerificationAuditRequiresHardening, Batch: 1, Notes: "Require bot identity response fields and suppress profile details."},
	"huggingface-token":         {Status: VerificationAuditRequiresHardening, Batch: 1, Notes: "Reconcile supported token formats and validate whoami response structure."},
	"groq-api-key":              {Status: VerificationAuditRequiresHardening, Batch: 1, Notes: "Require an OpenAI-compatible model-list response."},
	"replicate-token":           {Status: VerificationAuditRequiresHardening, Batch: 1, Notes: "Confirm current token length and validate account identity fields."},
	"airtable-pat":              {Status: VerificationAuditRequiresHardening, Batch: 1, Notes: "Validate whoami identity and scope responses."},
	"asana-pat":                 {Status: VerificationAuditRequiresHardening, Batch: 1, Notes: "Test both supported token formats and require data.gid."},
	"clickup-token":             {Status: VerificationAuditRequiresHardening, Batch: 1, Notes: "Require user identity response fields."},
	"typeform-token":            {Status: VerificationAuditRequiresHardening, Batch: 1, Notes: "Preserve structured authentication errors and validate user identity."},
	"hubspot-private-app-token": {Status: VerificationAuditRequiresHardening, Batch: 1, Notes: "Validate usage response and distinguish structured scope failures."},
	"mailchimp-key":             {Status: VerificationAuditRequiresHardening, Batch: 1, Notes: "Validate data-center suffix and ping response."},
	"klaviyo-key":               {Status: VerificationAuditRequiresHardening, Batch: 1, Notes: "Replace profile lookup with bounded account metadata."},
	"iterable-api-key":          {Status: VerificationAuditRequiresHardening, Batch: 1, Notes: "Resolve key type and region ambiguity before classifying rejection."},
	"nightfall-api-key":         {Status: VerificationAuditRequiresHardening, Batch: 1, Notes: "Validate the read-only detection-rules response."},
	"pinecone-api-key":          {Status: VerificationAuditRequiresHardening, Batch: 1, Notes: "Validate control-plane index response and permission errors."},
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
