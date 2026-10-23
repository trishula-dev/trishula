package bench

// Scenario encodes one §17.2 benchmark-plan row. Driveable marks the
// scenarios measurable in hosted CI on the in-repo engine path; Plane
// names the runtime each scenario must run on; Gate names what keeps a
// non-driveable scenario out of CI today (empty = unblocked).
type Scenario struct {
	ID        string
	Name      string
	Driveable bool
	Plane     string // ci | lab | kernel | nightly | blocked
	Gate      string // the absent runtime the scenario waits on
}

// Recipe is one measured request cell inside a scenario: a
// deterministic request recipe bound to the §17.1 budget row it reports
// against. Iterations and Warmup bound the hosted-CI measurement cost.
type Recipe struct {
	ID          string
	Scenario    string
	Method      string
	URI         string
	Body        string // deterministic request body ("" = no body)
	ContentType string
	Attack      bool // the recipe carries attack payloads (CRS matches expected)
	BudgetID    string
	Iterations  int
	Warmup      int
}

// Recipes returns the driveable request recipes for the CI-measurable
// scenarios (§17.2 rows 2, 3 and 7).
func Recipes() ([]Recipe, error) {
	return nil, errNotImplemented
}

// LoadScenarios returns the §17.2 scenario inventory.
func LoadScenarios() ([]Scenario, error) {
	return nil, errNotImplemented
}
