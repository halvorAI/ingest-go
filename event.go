package ingest

// Typed Agent Payment Event fields. Every optional field is omitted when empty, because APE
// v0.1 never allows null. You can also pass a map[string]any to [Client.Emit].
//
// Field reference: https://schema.halvorai.com

// Event types.
const (
	PaymentRequested  = "payment.requested"
	PaymentAuthorized = "payment.authorized"
	PaymentSettled    = "payment.settled"
	PaymentFailed     = "payment.failed"
	PaymentRefunded   = "payment.refunded"
	PaymentDisputed   = "payment.disputed"
)

// Event is the input to [Client.Emit]. The client fills ape_version, id, occurred_at,
// environment and source, and takes agent, owner and instruction from the context when the
// event leaves them out.
type Event struct {
	// ID is generated when empty. Set it to make retries idempotent: the API stores an id once.
	ID   string `json:"id,omitempty"`
	Type string `json:"type"`
	// OccurredAt is RFC 3339 UTC with milliseconds; the time of Emit when empty.
	OccurredAt string `json:"occurred_at,omitempty"`
	// Environment is the client's ("test" or "live") when empty.
	Environment string       `json:"environment,omitempty"`
	Source      *SourceInput `json:"source,omitempty"`
	Agent       *Agent       `json:"agent,omitempty"`
	Owner       *Owner       `json:"owner,omitempty"`
	Instruction *Instruction `json:"instruction,omitempty"`
	Payment     Payment      `json:"payment"`
	Payee       Payee        `json:"payee"`
	Instrument  *Instrument  `json:"instrument,omitempty"`
	Evidence    []Evidence   `json:"evidence,omitempty"`
	Related     *Related     `json:"related,omitempty"`
	// Labels: at most 20, keys up to 64 characters, values up to 256.
	Labels map[string]string `json:"labels,omitempty"`
}

// SourceInput lets an adapter name itself. The source id and SDK version always come from the
// client.
type SourceInput struct {
	Adapter string `json:"adapter,omitempty"`
}

// Agent is the AI agent that made the payment.
type Agent struct {
	ID            string `json:"id"`
	Name          string `json:"name,omitempty"`
	Framework     string `json:"framework,omitempty"`
	Version       string `json:"version,omitempty"`
	KeyThumbprint string `json:"key_thumbprint,omitempty"`
	KYA           *KYA   `json:"kya,omitempty"`
}

// KYA is a know-your-agent attestation reference.
type KYA struct {
	Provider   string `json:"provider"`
	Subject    string `json:"subject"`
	Assurance  string `json:"assurance,omitempty"`
	VerifiedAt string `json:"verified_at,omitempty"`
}

// Owner is the person or business the agent acts for.
type Owner struct {
	ID string `json:"id"`
	// Type is "person" or "business".
	Type        string `json:"type"`
	DisplayName string `json:"display_name,omitempty"`
	Country     string `json:"country,omitempty"`
	KYCRef      string `json:"kyc_ref,omitempty"`
}

// Instruction is what the agent was asked to do. Text is hashed on your machine and never
// sent; only ID, the hash and the other fields leave the process.
type Instruction struct {
	ID         string `json:"id"`
	Text       string `json:"text,omitempty"`
	Hash       string `json:"hash,omitempty"`
	Summary    string `json:"summary,omitempty"`
	Channel    string `json:"channel,omitempty"`
	IssuedAt   string `json:"issued_at,omitempty"`
	ToolCallID string `json:"tool_call_id,omitempty"`
}

// Payment is the payment itself.
type Payment struct {
	PaymentID string `json:"payment_id"`
	// Rail is stripe, card, x402, mpp, stablecoin or bank_transfer.
	Rail   string `json:"rail"`
	Amount Amount `json:"amount"`
	Status string `json:"status"`
	// RailRef holds the rail's own ids; only the keys defined for the rail are allowed.
	RailRef       map[string]any `json:"rail_ref"`
	FailureReason string         `json:"failure_reason,omitempty"`
	Description   string         `json:"description,omitempty"`
	Category      string         `json:"category,omitempty"`
}

// Amount is an integer string in minor units (with Currency) or atomic units (with Asset).
type Amount struct {
	Value    string `json:"value"`
	Unit     string `json:"unit"`
	Currency string `json:"currency,omitempty"`
	Asset    *Asset `json:"asset,omitempty"`
}

// Asset is an on-chain token.
type Asset struct {
	Network  string `json:"network"`
	Address  string `json:"address"`
	Symbol   string `json:"symbol,omitempty"`
	Decimals *int   `json:"decimals,omitempty"`
}

// Wallet is an address on a CAIP-2 network.
type Wallet struct {
	Network string `json:"network"`
	Address string `json:"address"`
}

// Payee is who was paid. It needs at least one of Name, ID or Wallet.
type Payee struct {
	Type        string  `json:"type"`
	Name        string  `json:"name,omitempty"`
	ID          string  `json:"id,omitempty"`
	Website     string  `json:"website,omitempty"`
	Country     string  `json:"country,omitempty"`
	MCC         string  `json:"mcc,omitempty"`
	Wallet      *Wallet `json:"wallet,omitempty"`
	ResourceURL string  `json:"resource_url,omitempty"`
}

// Instrument is what the agent paid with.
type Instrument struct {
	Type     string  `json:"type"`
	Network  string  `json:"network,omitempty"`
	Last4    string  `json:"last4,omitempty"`
	PAR      string  `json:"par,omitempty"`
	TokenRef string  `json:"token_ref,omitempty"`
	Wallet   *Wallet `json:"wallet,omitempty"`
	Issuer   string  `json:"issuer,omitempty"`
}

// Evidence is a signed artefact behind the payment. Set Value or URI. SHA256 is computed from
// Value when empty.
type Evidence struct {
	Kind       string `json:"kind"`
	Format     string `json:"format"`
	Value      any    `json:"value,omitempty"`
	URI        string `json:"uri,omitempty"`
	SHA256     string `json:"sha256,omitempty"`
	CapturedAt string `json:"captured_at,omitempty"`
}

// Related links this event to others.
type Related struct {
	PreviousEventID string `json:"previous_event_id,omitempty"`
	CorrectsEventID string `json:"corrects_event_id,omitempty"`
	SessionID       string `json:"session_id,omitempty"`
}

// Envelope is a signed event as sent to HalvorAI: the event and its detached JWS.
type Envelope struct {
	Event map[string]any `json:"event"`
	Sig   string         `json:"sig"`
}
