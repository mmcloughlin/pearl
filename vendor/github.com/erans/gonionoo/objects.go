package gonionoo

// RelaySummary document contains the information of a relay
type RelaySummary struct {
	Nickname              string   `json:"n"`
	Fingerprint           string   `json:"f"`
	RoutingConnectionsIPs []string `json:"a"`
	Running               bool     `json:"r"`
}

// BridgeSummary document contains the information of a brigde
type BridgeSummary struct {
	Nickname        string `json:"n"`
	FingerprintHash string `json:"h"`
	Running         bool   `json:"r"`
}

// Summary document contain short summaries of relays with nicknames, fingerprints, IP addresses, and running information as well as bridges with hashed fingerprints and running information
type Summary struct {
	Version                   string          `json:"version"`
	NextMajorVersionScheduled string          `json:"next_major_version_scheduled"`
	RelaysPublished           string          `json:"relays_published"`
	Relays                    []RelaySummary  `json:"relays"`
	BridgesPublished          string          `json:"bridges_published"`
	Bridges                   []BridgeSummary `json:"bridges"`
}

// RelayDetails document contains the detailed information about a relay
type RelayDetails struct {
	Nickname                 string              `json:"nickname"`
	Fingerprint              string              `json:"fingerprint"`
	OrAddresses              []string            `json:"or_addresses"`
	ExitAddresses            []string            `json:"exit_addresses"`
	DirAddress               string              `json:"dir_address"`
	LastSeen                 string              `json:"last_seen"`
	LastChangedAddressOrPort string              `json:"last_changed_address_or_port"`
	FirstSeen                string              `json:"first_seen"`
	Running                  bool                `json:"running"`
	Hibernating              bool                `json:"hibernating"`
	Flags                    []string            `json:"flags"`
	Country                  string              `json:"country"`
	CountryName              string              `json:"country_name"`
	RegionName               string              `json:"region_name"`
	CityName                 string              `json:"city_name"`
	Latitude                 float64             `json:"latitude"`
	Longitude                float64             `json:"longitude"`
	ASNumber                 string              `json:"as_number"`
	ASName                   string              `json:"as_name"`
	ConsensusWeight          float64             `json:"consensus_weight"`
	HostName                 string              `json:"host_name"`
	LastRestarted            string              `json:"last_restarted"`
	BandwidthRate            float64             `json:"bandwidth_rate"`
	BandwidthBurst           float64             `json:"bandwidth_burst"`
	ObservedBandwidth        float64             `json:"observed_bandwidth"`
	AdvertisedBandwidth      float64             `json:"advertised_bandwidth"`
	ExitPolicy               []string            `json:"exit_policy"`
	ExitPolicySummary        map[string][]string `json:"exit_policy_summary"`
	ExitPolicyV6Summary      map[string][]string `json:"exit_policy_v6_summary"`
	Contact                  string              `json:"contact"`
	Platfrom                 string              `json:"platform"`
	RecommendedVersion       bool                `json:"recommended_version"`
	EffectiveFamily          []string            `json:"effective_family"` // Added on July 3, 2015
	AllegedFamily            []string            `json:"alleged_family"`   // Added on August 25, 2015
	IndirectFamily           []string            `json:"indirect_family"`  // Added on August 25, 2015
	ConsensusWeightFraction  float64             `json:"consensus_weight_fraction"`
	GuardProbability         float64             `json:"guard_probability"`
	MiddleProbability        float64             `json:"middle_probability"`
	ExitProbability          float64             `json:"exit_probability"`
	Measured                 bool                `json:"measured"` // Added on August 13, 2015
}

// BridgeDetails document contains detailed information about a bridge
type BridgeDetails struct {
	Nickname            string   `json:"nickname"`
	HashedFingerprint   string   `json:"hashed_fingerprint"`
	ORAddresses         []string `json:"or_addresses"`
	LastSeen            string   `json:"last_seen"`
	FirstSeen           string   `json:"first_seen"`
	Running             bool     `json:"running"`
	Flags               []string `json:"flags"`
	LastRestarted       string   `json:"last_restarted"`
	AdvertisedBandwidth float64  `json:"advertised_bandwidth"`
	Platform            string   `json:"platform"`
	Transports          []string `json:"transports"`
}

// Details documents are based on network statuses published by the Tor directories, server descriptors published by relays and bridges, and data published by Tor network services TorDNSEL and BridgeDB. Details documents use the most recently published data from these sources, which may lead to contradictions between fields based on different sources in rare edge cases.
type Details struct {
	Version                   string          `json:"version"`
	NextMajorVersionScheduled string          `json:"next_major_version_scheduled"`
	RelaysPublished           string          `json:"relays_published"`
	Relays                    []RelayDetails  `json:"relays"`
	BridgesPublished          string          `json:"bridges_published"`
	Bridges                   []BridgeDetails `json:"bridges"`
}

// GraphHistory object contains history data that can be plotted
type GraphHistory struct {
	First    string  `json:"first"`
	Last     string  `json:"last"`
	Interval int32   `json:"interval"`
	Factor   float64 `json:"factor"`
	Count    int32   `json:"count"`
	Values   []int32 `json:"values"`
}

// GraphHistoryBeta is a new format in Beta that breaks that GraphHistory format. It has some additional fields
type GraphHistoryBeta struct {
	First      string             `json:"first"`
	Last       string             `json:"last"`
	Interval   int32              `json:"interval"`
	Factor     float64            `json:"factor"`
	Count      int32              `json:"count"`
	Values     []int32            `json:"values"`
	Countries  map[string]float64 `json:"countries"`
	Transports map[string]float64 `json:"transports"`
	Versions   map[string]float64 `json:"versions"`
}

// RelayBandwidth object contains bandwidth historical data for a relay
type RelayBandwidth struct {
	Fingerprint  string                  `json:"fingerprint"`
	WriteHistory map[string]GraphHistory `json:"write_history"`
	ReadHistory  map[string]GraphHistory `json:"read_history"`
}

// BridgeBandwidth object contains bandwidth historical data for a bridge
type BridgeBandwidth struct {
	Fingerprint  string                  `json:"fingerprint"`
	WriteHistory map[string]GraphHistory `json:"write_history"`
	ReadHistory  map[string]GraphHistory `json:"read_history"`
}

// Bandwidth documents contain aggregate statistics of a relay's or bridge's consumed bandwidth for different time intervals. Bandwidth documents are only updated when a relay or bridge publishes a new server descriptor, which may take up to 18 hours during normal operation
type Bandwidth struct {
	Version                   string            `json:"version"`
	NextMajorVersionScheduled string            `json:"next_major_version_scheduled"`
	RelaysPublished           string            `json:"relays_published"`
	Relays                    []RelayBandwidth  `json:"relays"`
	BridgesPublished          string            `json:"bridges_published"`
	Bridges                   []BridgeBandwidth `json:"bridges"`
}

// RelayWeight contains weight data from a specific relay
type RelayWeight struct {
	Fingerprint             string                  `json:"fingerprint"`
	ConsensusWeightFraction map[string]GraphHistory `json:"consensus_weight_fraction"`
	GuardProbability        map[string]GraphHistory `json:"guard_probability"`
	MiddleProbability       map[string]GraphHistory `json:"middle_probability"`
	ExitProbability         map[string]GraphHistory `json:"exit_probability"`
	ConsensusWeight         map[string]GraphHistory `json:"consensus_weight"`
}

// Weights documents contain aggregate statistics of a relay's probability to be selected by clients for building paths. Weights documents contain different time intervals and are available for relays only
type Weights struct {
	Version                   string        `json:"version"`
	NextMajorVersionScheduled string        `json:"next_major_version_scheduled"`
	RelaysPublished           string        `json:"relays_published"`
	Relays                    []RelayWeight `json:"relays"`
	BridgesPublished          string        `json:"bridges_published"` // Only included for compatibility reasons with the other document types.
	Bridges                   []string      `json:"bridges"`           // Empty array of objects that would represent bridge weights documents. Only included for compatibility reasons with the other document types.
}

// BridgeClients contains the stats on average clients for that bridge
type BridgeClients struct {
	Fingerprint    string                      `json:"fingerprint"`
	AverageClients map[string]GraphHistoryBeta `json:"average_clients"`
}

// Clients documents contain estimates of the average number of clients connecting to a bridge every day. There are no clients documents available for relays, just for bridges. Clients documents contain different time intervals and are available for bridges only
type Clients struct {
	Version                   string          `json:"version"`
	NextMajorVersionScheduled string          `json:"next_major_version_scheduled"`
	RelaysPublished           string          `json:"relays_published"` // Only included for compatibility reasons with the other document types.
	Relays                    []string        `json:"relays"`           // Empty array of objects that would represent relay clients documents. Only included for compatibility reasons with the other document types.
	BridgesPublished          string          `json:"bridges_published"`
	Bridges                   []BridgeClients `json:"bridges"`
}

// RelayUptime represents a single relay uptime data
type RelayUptime struct {
	Fingerprint string                             `json:"fingerprint"`
	Uptime      map[string]GraphHistory            `json:"uptime"`
	Flags       map[string]map[string]GraphHistory `json:"flags"`
}

// BridgeUptime represetns a single bridge uptime data
type BridgeUptime struct {
	Fingerprint string                  `json:"fingerprint"`
	Uptime      map[string]GraphHistory `json:"uptime"`
}

// Uptime documents contain fractional uptimes of relays and bridges. Uptime documents contain different time intervals and are available for relays and bridges.
type Uptime struct {
	Version                   string         `json:"version"`
	NextMajorVersionScheduled string         `json:"next_major_version_scheduled"`
	RelaysPublished           string         `json:"relays_published"`
	Relays                    []RelayUptime  `json:"relays"`
	BridgesPublished          string         `json:"bridges_published"`
	Bridges                   []BridgeUptime `json:"bridges"`
}
