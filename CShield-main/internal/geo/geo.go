package geo

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"
)

type Info struct {
	IP          string  `json:"ip"`
	Country     string  `json:"country"`
	CountryCode string  `json:"country_code"`
	Region      string  `json:"region"`
	City        string  `json:"city"`
	Lat         float64 `json:"lat"`
	Lon         float64 `json:"lon"`
	ASN         string  `json:"asn"`
	Org         string  `json:"org"`
	Timezone    string  `json:"timezone"`
	UpdatedAt   int64   `json:"updated_at"`
}

type Resolver struct {
	mu    sync.Mutex
	cache map[string]Info
	http  *http.Client
}

func NewResolver() *Resolver {
	return &Resolver{
		cache: map[string]Info{},
		http:  &http.Client{Timeout: 1500 * time.Millisecond},
	}
}

 // try primary provider: ipapi.co
func (r *Resolver) lookupIPAPI(ip string, now int64) (Info, bool) {
	req, err := http.NewRequest("GET", "http://ipapi.co/"+ip+"/json/", nil)
	if err != nil {
		return Info{}, false
	}
	req.Header.Set("User-Agent", "cshield-geo/1.0")
	resp, err := r.http.Do(req)
	if err != nil {
		return Info{}, false
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return Info{}, false
	}
	var raw struct {
		IP          string  `json:"ip"`
		Country     string  `json:"country_name"`
		CountryCode string  `json:"country"`
		Region      string  `json:"region"`
		City        string  `json:"city"`
		Lat         float64 `json:"latitude"`
		Lon         float64 `json:"longitude"`
		ASN         string  `json:"asn"`
		Org         string  `json:"org"`
		Timezone    string  `json:"timezone"`
	}
	if json.NewDecoder(resp.Body).Decode(&raw) != nil {
		return Info{}, false
	}
	if raw.Country == "" && raw.CountryCode == "" {
		return Info{}, false
	}
	return Info{
		IP:          ip,
		Country:     raw.Country,
		CountryCode: strings.ToUpper(raw.CountryCode),
		Region:      raw.Region,
		City:        raw.City,
		Lat:         raw.Lat,
		Lon:         raw.Lon,
		ASN:         normalizeASN(raw.ASN),
		Org:         raw.Org,
		Timezone:    raw.Timezone,
		UpdatedAt:   now,
	}, true
}

// fallback provider: ip-api.com
func (r *Resolver) lookupIPAPIAlt(ip string, now int64) (Info, bool) {
	req, err := http.NewRequest("GET", "http://ip-api.com/json/"+ip+"?fields=status,message,country,countryCode,regionName,city,lat,lon,as,org,timezone,query", nil)
	if err != nil {
		return Info{}, false
	}
	req.Header.Set("User-Agent", "cshield-geo/1.0")
	resp, err := r.http.Do(req)
	if err != nil {
		return Info{}, false
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return Info{}, false
	}
	var raw struct {
		Status      string  `json:"status"`
		Message     string  `json:"message"`
		Country     string  `json:"country"`
		CountryCode string  `json:"countryCode"`
		RegionName  string  `json:"regionName"`
		City        string  `json:"city"`
		Lat         float64 `json:"lat"`
		Lon         float64 `json:"lon"`
		ASN         string  `json:"as"`
		Org         string  `json:"org"`
		Timezone    string  `json:"timezone"`
	}
	if json.NewDecoder(resp.Body).Decode(&raw) != nil {
		return Info{}, false
	}
	if strings.ToLower(raw.Status) != "success" {
		return Info{}, false
	}
	if raw.Country == "" && raw.CountryCode == "" {
		return Info{}, false
	}
	return Info{
		IP:          ip,
		Country:     raw.Country,
		CountryCode: strings.ToUpper(raw.CountryCode),
		Region:      raw.RegionName,
		City:        raw.City,
		Lat:         raw.Lat,
		Lon:         raw.Lon,
		ASN:         normalizeASN(raw.ASN),
		Org:         raw.Org,
		Timezone:    raw.Timezone,
		UpdatedAt:   now,
	}, true
}

func (r *Resolver) Lookup(ip string) (Info, bool) {
	if ip == "" {
		return Info{}, false
	}
	now := time.Now().Unix()

	// check cache first
	r.mu.Lock()
	if v, ok := r.cache[ip]; ok {
		if now-v.UpdatedAt < 21600 {
			r.mu.Unlock()
			return v, true
		}
	}
	r.mu.Unlock()

	// primary provider
	if out, ok := r.lookupIPAPI(ip, now); ok {
		r.mu.Lock()
		r.cache[ip] = out
		r.mu.Unlock()
		return out, true
	}

	// fallback provider
	if out, ok := r.lookupIPAPIAlt(ip, now); ok {
		r.mu.Lock()
		r.cache[ip] = out
		r.mu.Unlock()
		return out, true
	}

	return Info{}, false
}

func normalizeASN(asn string) string {
	asn = strings.TrimSpace(asn)
	if asn == "" {
		return ""
	}

	// Take the first token (e.g. "AS12345" from "AS12345 Example Network")
	fields := strings.Fields(asn)
	if len(fields) == 0 {
		return ""
	}
	token := strings.ToUpper(fields[0])

	// If it already starts with "AS", return as-is (uppercased)
	if strings.HasPrefix(token, "AS") {
		return token
	}

	// If it's purely numeric, prefix with "AS"
	allDigits := true
	for _, ch := range token {
		if ch < '0' || ch > '9' {
			allDigits = false
			break
		}
	}
	if allDigits {
		return "AS" + token
	}

	// Fallback: return the cleaned token
	return token
}