// Command seed generates a realistic test dataset for the Lumina Fraud API
// and writes it to data/seed.json.
//
// Usage:
//
//	go run ./cmd/seed
//
// The generated dataset contains ~310 transactions spanning 7 days with the
// distribution specified in the challenge brief:
//   - 70-80% normal (low-risk) transactions from consistent LATAM users
//   - 10-15% velocity abuse (rapid purchases from same entity)
//   - 5-10% geographic mismatches
//   - 3-5% high-value outliers (first purchase 10x the average)
package main

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"time"

	"lumina/fraud-api/internal/domain"
)

func main() {
	rng := rand.New(rand.NewSource(42)) // deterministic seed for reproducibility

	baseTime := time.Now().UTC().Add(-7 * 24 * time.Hour)
	var transactions []domain.TransactionRequest

	transactions = append(transactions, generateNormalUsers(rng, baseTime)...)
	transactions = append(transactions, generateVelocityAbuse(rng, baseTime)...)
	transactions = append(transactions, generateGeoMismatches(rng, baseTime)...)
	transactions = append(transactions, generateHighValueOutliers(rng, baseTime)...)
	transactions = append(transactions, generateObviousFraudsters(rng, baseTime)...)

	// Shuffle so patterns aren't trivially grouped in the file.
	rng.Shuffle(len(transactions), func(i, j int) {
		transactions[i], transactions[j] = transactions[j], transactions[i]
	})

	if err := os.MkdirAll("data", 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "mkdir error: %v\n", err)
		os.Exit(1)
	}

	f, err := os.Create("data/seed.json")
	if err != nil {
		fmt.Fprintf(os.Stderr, "create error: %v\n", err)
		os.Exit(1)
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(transactions); err != nil {
		fmt.Fprintf(os.Stderr, "encode error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Generated %d transactions → data/seed.json\n", len(transactions))
}

// ─── Normal users (~225 transactions, 73%) ────────────────────────────────────

// normalUser describes a consistent, legitimate Lumina player.
type normalUser struct {
	email       string
	ip          string
	ipCountry   string
	cardBIN     string
	cardCountry string
	merchantCo  string
	currency    string
	device      string
	accountAge  time.Duration // account age at the start of the 7-day window
	avgAmount   float64
}

var normalUsers = []normalUser{
	{
		email: "carlos.silva@gmail.com", ip: "177.23.45.12", ipCountry: "BR",
		cardBIN: "453211", cardCountry: "BR", merchantCo: "BR", currency: domain.BRL,
		device: "dev_br_a1b2c3", accountAge: 365 * 24 * time.Hour, avgAmount: 35.0,
	},
	{
		email: "sofia.ramirez@hotmail.com", ip: "187.65.12.34", ipCountry: "MX",
		cardBIN: "524571", cardCountry: "MX", merchantCo: "MX", currency: domain.MXN,
		device: "dev_mx_d4e5f6", accountAge: 200 * 24 * time.Hour, avgAmount: 150.0,
	},
	{
		email: "diego.moreno@yahoo.com.ar", ip: "200.45.67.89", ipCountry: "AR",
		cardBIN: "516382", cardCountry: "AR", merchantCo: "AR", currency: domain.ARS,
		device: "dev_ar_g7h8i9", accountAge: 500 * 24 * time.Hour, avgAmount: 800.0,
	},
	{
		email: "ana.garcia@gmail.com", ip: "190.122.33.44", ipCountry: "CO",
		cardBIN: "455231", cardCountry: "CO", merchantCo: "CO", currency: domain.COP,
		device: "dev_co_j1k2l3", accountAge: 150 * 24 * time.Hour, avgAmount: 45000.0,
	},
	{
		email: "pedro.oliveira@gmail.com", ip: "187.12.99.10", ipCountry: "BR",
		cardBIN: "456789", cardCountry: "BR", merchantCo: "BR", currency: domain.BRL,
		device: "dev_br_m4n5o6", accountAge: 730 * 24 * time.Hour, avgAmount: 28.0,
	},
	{
		email: "maria.lopez@protonmail.com", ip: "189.200.11.22", ipCountry: "MX",
		cardBIN: "541283", cardCountry: "MX", merchantCo: "MX", currency: domain.MXN,
		device: "dev_mx_p7q8r9", accountAge: 90 * 24 * time.Hour, avgAmount: 200.0,
	},
	{
		email: "juan.hernandez@gmail.com", ip: "201.33.55.77", ipCountry: "AR",
		cardBIN: "531904", cardCountry: "AR", merchantCo: "AR", currency: domain.ARS,
		device: "dev_ar_s1t2u3", accountAge: 400 * 24 * time.Hour, avgAmount: 600.0,
	},
	{
		email: "valentina.torres@icloud.com", ip: "181.78.90.12", ipCountry: "CO",
		cardBIN: "461234", cardCountry: "CO", merchantCo: "CO", currency: domain.COP,
		device: "dev_co_v4w5x6", accountAge: 300 * 24 * time.Hour, avgAmount: 38000.0,
	},
	{
		email: "lucas.costa@gmail.com", ip: "187.44.88.21", ipCountry: "BR",
		cardBIN: "459012", cardCountry: "BR", merchantCo: "BR", currency: domain.BRL,
		device: "dev_br_y7z8a9", accountAge: 180 * 24 * time.Hour, avgAmount: 55.0,
	},
	{
		email: "isabella.flores@live.com", ip: "200.87.54.32", ipCountry: "MX",
		cardBIN: "552398", cardCountry: "MX", merchantCo: "MX", currency: domain.MXN,
		device: "dev_mx_b1c2d3", accountAge: 60 * 24 * time.Hour, avgAmount: 175.0,
	},
}

func generateNormalUsers(rng *rand.Rand, base time.Time) []domain.TransactionRequest {
	var txns []domain.TransactionRequest
	txID := 1000

	for _, u := range normalUsers {
		// Each "known good" user makes 20-24 transactions spread over 7 days.
		count := 20 + rng.Intn(5)
		accountCreated := base.Add(-u.accountAge)

		for i := 0; i < count; i++ {
			// Spread evenly across 7 days with some randomness.
			hoursIntoWindow := float64(i) * (7*24.0 / float64(count))
			jitter := rng.Float64() * 2 // ±2 hours
			ts := base.Add(time.Duration((hoursIntoWindow+jitter)*float64(time.Hour)))

			// Amounts vary ±30% around the user's average.
			amount := u.avgAmount * (0.7 + rng.Float64()*0.6)
			amount = roundTo2(amount)

			txns = append(txns, domain.TransactionRequest{
				TransactionID:     fmt.Sprintf("txn_%05d", txID),
				Timestamp:         ts,
				Amount:            amount,
				Currency:          u.currency,
				UserEmail:         u.email,
				IPAddress:         u.ip,
				IPCountry:         u.ipCountry,
				CardBIN:           u.cardBIN,
				CardCountry:       u.cardCountry,
				DeviceFingerprint: u.device,
				AccountCreatedAt:  accountCreated,
				MerchantCountry:   u.merchantCo,
			})
			txID++
		}
	}
	return txns
}

// ─── Velocity abuse (~40 transactions, 13%) ───────────────────────────────────

func generateVelocityAbuse(rng *rand.Rand, base time.Time) []domain.TransactionRequest {
	var txns []domain.TransactionRequest
	txID := 2000

	// Group 1: same email, burst of 8 purchases in 15 minutes (Day 3)
	burstStart := base.Add(3*24*time.Hour + 14*time.Hour)
	accountCreated := base.Add(-10 * 24 * time.Hour)
	for i := 0; i < 8; i++ {
		ts := burstStart.Add(time.Duration(i*2) * time.Minute)
		txns = append(txns, domain.TransactionRequest{
			TransactionID:     fmt.Sprintf("txn_%05d", txID),
			Timestamp:         ts,
			Amount:            roundTo2(49.90 + rng.Float64()*5),
			Currency:          domain.BRL,
			UserEmail:         "velocity_abuser1@tempmail.com",
			IPAddress:         "201.55.66.77",
			IPCountry:         "BR",
			CardBIN:           "453211",
			CardCountry:       "BR",
			DeviceFingerprint: "dev_velocity_aaa",
			AccountCreatedAt:  accountCreated,
			MerchantCountry:   "BR",
		})
		txID++
	}

	// Group 2: same IP, 10 different users buying in the same 30-minute window (Day 5)
	ipAbuseStart := base.Add(5*24*time.Hour + 20*time.Hour)
	emails := []string{
		"user_a@test.com", "user_b@test.com", "user_c@test.com", "user_d@test.com",
		"user_e@test.com", "user_f@test.com", "user_g@test.com", "user_h@test.com",
		"user_i@test.com", "user_j@test.com",
	}
	for i, email := range emails {
		ts := ipAbuseStart.Add(time.Duration(i*3) * time.Minute)
		acc := ts.Add(-time.Duration(1+rng.Intn(5)) * 24 * time.Hour)
		txns = append(txns, domain.TransactionRequest{
			TransactionID:     fmt.Sprintf("txn_%05d", txID),
			Timestamp:         ts,
			Amount:            roundTo2(99.0 + rng.Float64()*50),
			Currency:          domain.MXN,
			UserEmail:         email,
			IPAddress:         "189.45.123.200",
			IPCountry:         "MX",
			CardBIN:           "524571",
			CardCountry:       "MX",
			DeviceFingerprint: fmt.Sprintf("dev_ipabuse_%02d", i),
			AccountCreatedAt:  acc,
			MerchantCountry:   "MX",
		})
		txID++
	}

	// Group 3: device reuse — same device fingerprint across 6 transactions, 3 emails (Day 6)
	deviceAbuseStart := base.Add(6*24*time.Hour + 9*time.Hour)
	deviceEmails := []string{"fraud_d1@mail.com", "fraud_d2@mail.com", "fraud_d3@mail.com"}
	for i := 0; i < 6; i++ {
		ts := deviceAbuseStart.Add(time.Duration(i*4) * time.Minute)
		email := deviceEmails[i%3]
		acc := ts.Add(-2 * time.Hour)
		txns = append(txns, domain.TransactionRequest{
			TransactionID:     fmt.Sprintf("txn_%05d", txID),
			Timestamp:         ts,
			Amount:            roundTo2(1200 + rng.Float64()*300),
			Currency:          domain.ARS,
			UserEmail:         email,
			IPAddress:         "200.12.34.56",
			IPCountry:         "AR",
			CardBIN:           "531904",
			CardCountry:       "AR",
			DeviceFingerprint: "dev_shared_fingerprint_xyz",
			AccountCreatedAt:  acc,
			MerchantCountry:   "AR",
		})
		txID++
	}

	return txns
}

// ─── Geographic mismatches (~20 transactions, 6%) ─────────────────────────────

func generateGeoMismatches(rng *rand.Rand, base time.Time) []domain.TransactionRequest {
	var txns []domain.TransactionRequest
	txID := 3000

	mismatches := []struct {
		email, ip, ipCountry, cardBIN, cardCountry, device, currency, merchant string
		accountDays int
		amount      float64
	}{
		// Russian IP using a Brazilian card
		{
			email: "buyer1@proton.me", ip: "185.100.87.12", ipCountry: "RU",
			cardBIN: "453211", cardCountry: "BR", device: "dev_geo_001",
			currency: domain.BRL, merchant: "BR", accountDays: 5, amount: 89.90,
		},
		{
			email: "buyer1@proton.me", ip: "185.100.87.12", ipCountry: "RU",
			cardBIN: "453211", cardCountry: "BR", device: "dev_geo_001",
			currency: domain.BRL, merchant: "BR", accountDays: 5, amount: 99.90,
		},
		// Nigerian IP using a Mexican card
		{
			email: "shopper99@webmail.com", ip: "196.216.2.5", ipCountry: "NG",
			cardBIN: "524571", cardCountry: "MX", device: "dev_geo_002",
			currency: domain.MXN, merchant: "MX", accountDays: 2, amount: 349.0,
		},
		// Chinese IP using an Argentine card in a Colombian merchant
		{
			email: "gamer_cn@outlook.com", ip: "112.77.11.22", ipCountry: "CN",
			cardBIN: "516382", cardCountry: "AR", device: "dev_geo_003",
			currency: domain.COP, merchant: "CO", accountDays: 1, amount: 75000.0,
		},
		// Ukrainian IP using a Colombian card
		{
			email: "vitali_k@inbox.ua", ip: "91.200.12.33", ipCountry: "UA",
			cardBIN: "455231", cardCountry: "CO", device: "dev_geo_004",
			currency: domain.COP, merchant: "CO", accountDays: 30, amount: 120000.0,
		},
	}

	for i, m := range mismatches {
		// Spread across days 1–6
		ts := base.Add(time.Duration(1+i)*24*time.Hour + time.Duration(10+rng.Intn(8))*time.Hour)
		acc := ts.Add(-time.Duration(m.accountDays) * 24 * time.Hour)

		for j := 0; j < 4; j++ { // 4 transactions each = 20 total
			jitterHours := time.Duration(rng.Intn(48)) * time.Hour
			txns = append(txns, domain.TransactionRequest{
				TransactionID:     fmt.Sprintf("txn_%05d", txID),
				Timestamp:         ts.Add(jitterHours),
				Amount:            roundTo2(m.amount * (0.8 + rng.Float64()*0.4)),
				Currency:          m.currency,
				UserEmail:         m.email,
				IPAddress:         m.ip,
				IPCountry:         m.ipCountry,
				CardBIN:           m.cardBIN,
				CardCountry:       m.cardCountry,
				DeviceFingerprint: m.device,
				AccountCreatedAt:  acc,
				MerchantCountry:   m.merchant,
			})
			txID++
		}
	}

	return txns
}

// ─── High-value outliers (~12 transactions, 4%) ───────────────────────────────

func generateHighValueOutliers(rng *rand.Rand, base time.Time) []domain.TransactionRequest {
	var txns []domain.TransactionRequest
	txID := 4000

	outliers := []struct {
		email, ip, ipCountry, cardBIN, cardCountry, device, currency, merchant string
		accountDays int
		amount      float64
	}{
		// Brand new account, first purchase is $500 BRL (should be ~R$35 average for BR users)
		{
			email: "newuser_outlier1@gmail.com", ip: "187.11.22.33", ipCountry: "BR",
			cardBIN: "456789", cardCountry: "BR", device: "dev_out_001",
			currency: domain.BRL, merchant: "BR", accountDays: 0, amount: 500.0,
		},
		// New account, first purchase $2000 MXN — 10x the average MXN user
		{
			email: "newuser_outlier2@hotmail.com", ip: "189.66.77.88", ipCountry: "MX",
			cardBIN: "524571", cardCountry: "MX", device: "dev_out_002",
			currency: domain.MXN, merchant: "MX", accountDays: 0, amount: 2000.0,
		},
		// Week-old account, first large ARS purchase
		{
			email: "newuser_outlier3@outlook.com", ip: "200.55.66.77", ipCountry: "AR",
			cardBIN: "516382", cardCountry: "AR", device: "dev_out_003",
			currency: domain.ARS, merchant: "AR", accountDays: 6, amount: 15000.0,
		},
		// Established account making a genuine outlier purchase (VIP tournament)
		{
			email: "high_roller@gmail.com", ip: "190.200.11.33", ipCountry: "CO",
			cardBIN: "461234", cardCountry: "CO", device: "dev_out_004",
			currency: domain.COP, merchant: "CO", accountDays: 180, amount: 500000.0,
		},
	}

	for i, o := range outliers {
		ts := base.Add(time.Duration(2+i)*24*time.Hour + 15*time.Hour)
		var acc time.Time
		if o.accountDays == 0 {
			acc = ts.Add(-30 * time.Minute) // brand new
		} else {
			acc = ts.Add(-time.Duration(o.accountDays) * 24 * time.Hour)
		}

		for j := 0; j < 3; j++ {
			txns = append(txns, domain.TransactionRequest{
				TransactionID:     fmt.Sprintf("txn_%05d", txID),
				Timestamp:         ts.Add(time.Duration(j*24) * time.Hour),
				Amount:            roundTo2(o.amount * (0.9 + rng.Float64()*0.2)),
				Currency:          o.currency,
				UserEmail:         o.email,
				IPAddress:         o.ip,
				IPCountry:         o.ipCountry,
				CardBIN:           o.cardBIN,
				CardCountry:       o.cardCountry,
				DeviceFingerprint: o.device,
				AccountCreatedAt:  acc,
				MerchantCountry:   o.merchant,
			})
			txID++
		}
	}

	return txns
}

// ─── Obvious fraudsters (~15 transactions, 5%) ────────────────────────────────

// generateObviousFraudsters creates accounts with textbook fraud patterns:
// created at 3am, burst purchases, multiple different cards, geographic mismatch.
func generateObviousFraudsters(rng *rand.Rand, base time.Time) []domain.TransactionRequest {
	var txns []domain.TransactionRequest
	txID := 5000

	// Fraudster 1: account created at 3am, 5 purchases in 8 minutes, high-risk BIN
	fraudStart1 := base.Add(2*24*time.Hour + 3*time.Hour) // Day 2, 03:00 UTC
	accountCreated1 := fraudStart1.Add(-15 * time.Minute)  // account is 15 min old
	fraudCards1 := []string{"400000", "411111", "420000", "490000", "510000"}

	for i, bin := range fraudCards1 {
		ts := fraudStart1.Add(time.Duration(i*100) * time.Second) // ~1.5 min between purchases
		txns = append(txns, domain.TransactionRequest{
			TransactionID:     fmt.Sprintf("txn_%05d", txID),
			Timestamp:         ts,
			Amount:            99.99,
			Currency:          domain.BRL,
			UserEmail:         "fraud_ring_1@tempbox.net",
			IPAddress:         "185.220.101.5", // known Tor exit node range
			IPCountry:         "RU",
			CardBIN:           bin,
			CardCountry:       "US",
			DeviceFingerprint: "dev_fraud_ring_001",
			AccountCreatedAt:  accountCreated1,
			MerchantCountry:   "BR",
		})
		txID++
	}

	// Fraudster 2: card cycling, multiple cards from a single IP over 2 hours
	cyclingStart := base.Add(4*24*time.Hour + 22*time.Hour)
	cyclingCards := []string{"552000", "524571", "516382", "531904", "455231", "461234"}
	accountCreated2 := cyclingStart.Add(-6 * time.Hour)

	for i, bin := range cyclingCards {
		ts := cyclingStart.Add(time.Duration(i*20) * time.Minute)
		txns = append(txns, domain.TransactionRequest{
			TransactionID:     fmt.Sprintf("txn_%05d", txID),
			Timestamp:         ts,
			Amount:            roundTo2(500 + rng.Float64()*200),
			Currency:          domain.MXN,
			UserEmail:         fmt.Sprintf("carder_%02d@fastmail.com", i),
			IPAddress:         "103.91.92.200",
			IPCountry:         "CN",
			CardBIN:           bin,
			CardCountry:       "MX",
			DeviceFingerprint: "dev_fraud_ring_002",
			AccountCreatedAt:  accountCreated2,
			MerchantCountry:   "MX",
		})
		txID++
	}

	// Fraudster 3: high-risk BIN + new account + off-hours + geo mismatch
	fraudStart3 := base.Add(6*24*time.Hour + 4*time.Hour) // Day 6, 04:00 UTC
	accountCreated3 := fraudStart3.Add(-20 * time.Minute)

	for i := 0; i < 4; i++ {
		ts := fraudStart3.Add(time.Duration(i*3) * time.Minute)
		txns = append(txns, domain.TransactionRequest{
			TransactionID:     fmt.Sprintf("txn_%05d", txID),
			Timestamp:         ts,
			Amount:            roundTo2(149.99 + rng.Float64()*50),
			Currency:          domain.ARS,
			UserEmail:         "obvious_fraud@disposable.xyz",
			IPAddress:         "196.216.2.100",
			IPCountry:         "NG",
			CardBIN:           "601100",
			CardCountry:       "US",
			DeviceFingerprint: "dev_fraud_ring_003",
			AccountCreatedAt:  accountCreated3,
			MerchantCountry:   "AR",
		})
		txID++
	}

	return txns
}

// ─── Utilities ────────────────────────────────────────────────────────────────

func roundTo2(f float64) float64 {
	return float64(int(f*100)) / 100
}
