package ingest

import "context"

// AgentContext attributes payments to an agent, its owner and the instruction it was given.
type AgentContext struct {
	Agent       *Agent
	Owner       *Owner
	Instruction *Instruction
}

type contextKey struct{}

// WithAgentContext returns a context that attributes every event emitted with it. Fields left
// nil keep the value of an outer agent context.
//
//	ctx = ingest.WithAgentContext(ctx, ingest.AgentContext{
//		Agent: &ingest.Agent{ID: "agt_travel_12", Name: "Travel booking agent"},
//		Owner: &ingest.Owner{ID: "own_u_4410", Type: "person", Country: "US"},
//	})
//	client.Emit(ctx, event)
func WithAgentContext(ctx context.Context, ac AgentContext) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	if outer, ok := AgentContextFrom(ctx); ok {
		if ac.Agent == nil {
			ac.Agent = outer.Agent
		}
		if ac.Owner == nil {
			ac.Owner = outer.Owner
		}
		if ac.Instruction == nil {
			ac.Instruction = outer.Instruction
		}
	}
	return context.WithValue(ctx, contextKey{}, ac)
}

// AgentContextFrom returns the agent context set by [WithAgentContext], if any.
func AgentContextFrom(ctx context.Context) (AgentContext, bool) {
	if ctx == nil {
		return AgentContext{}, false
	}
	ac, ok := ctx.Value(contextKey{}).(AgentContext)
	return ac, ok
}
