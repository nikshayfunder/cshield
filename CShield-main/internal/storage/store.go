package storage

import (
	"context"
	"encoding/json"
	"sort"
	"strconv"
	"time"

	redis "github.com/redis/go-redis/v9"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type Ban struct {
	IP        string `json:"ip" bson:"ip"`
	Permanent bool   `json:"permanent" bson:"permanent"`
	ExpiresAt int64  `json:"expires_at" bson:"expires_at"`
	CreatedAt int64  `json:"created_at" bson:"created_at"`
}

type IPEvent struct {
	IP        string `bson:"ip"`
	FirstSeen int64  `bson:"first_seen"`
	LastSeen  int64  `bson:"last_seen"`
	Count     int64  `bson:"count"`
}

type Store struct {
	rdb    *redis.Client
	coll   *mongo.Collection
	ipColl *mongo.Collection
}

type Meta struct {
	IP          string `json:"ip"`
	Country     string `json:"country"`
	CountryCode string `json:"country_code"`
	ASN         string `json:"asn"`
	Org         string `json:"org"`
	Risk        int64  `json:"risk"`
	UpdatedAt   int64  `json:"updated_at"`
}

func New(redisAddr, redisPassword string, redisDB int, mongoURI, mongoDB string) (*Store, error) {
	if redisAddr == "" {
		redisAddr = "127.0.0.1:6379"
	}
	if mongoURI == "" {
		mongoURI = "mongodb://127.0.0.1:27017"
	}
	if mongoDB == "" {
		mongoDB = "cshield"
	}

	rdb := redis.NewClient(&redis.Options{
		Addr:     redisAddr,
		Password: redisPassword,
		DB:       redisDB,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := rdb.Ping(ctx).Err(); err != nil {
		rdb = nil
	}

	mc, err := mongo.Connect(ctx, options.Client().ApplyURI(mongoURI))
	if err != nil {
		if rdb != nil {
			_ = rdb.Close()
		}
		return nil, err
	}
	bans := mc.Database(mongoDB).Collection("bans")
	ipColl := mc.Database(mongoDB).Collection("ips")

	return &Store{rdb: rdb, coll: bans, ipColl: ipColl}, nil
}

func (s *Store) Init() error {
	if s == nil || s.coll == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := s.coll.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys:    bson.D{{Key: "ip", Value: 1}},
		Options: options.Index().SetUnique(true),
	})
	if err != nil {
		return err
	}
	go s.moveForeverToMongoLoop()
	return nil
}

func (s *Store) Close() error {
	if s == nil {
		return nil
	}
	if s.rdb != nil {
		_ = s.rdb.Close()
	}
	if s.coll != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return s.coll.Database().Client().Disconnect(ctx)
	}
	return nil
}

func (s *Store) SaveDrop(ip string, permanent bool, ttlSeconds int) error {
	if s == nil {
		return nil
	}
	now := time.Now().Unix()
	exp := int64(-1)
	if !permanent {
		if ttlSeconds <= 0 {
			ttlSeconds = 3600
		}
		exp = now + int64(ttlSeconds)
	}
	b := Ban{
		IP:        ip,
		Permanent: permanent,
		ExpiresAt: exp,
		CreatedAt: now,
	}
	if s.coll != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_, err := s.coll.UpdateOne(ctx, bson.M{"ip": b.IP}, bson.M{"$set": b}, options.Update().SetUpsert(true))
		if err != nil {
			return err
		}
	}
	if s.rdb != nil {
		data, err := json.Marshal(b)
		if err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		key := "ban:" + ip
		if err := s.rdb.Set(ctx, key, data, 0).Err(); err != nil {
			return err
		}
		if !permanent {
			_ = s.rdb.Expire(ctx, key, time.Duration(ttlSeconds)*time.Second).Err()
		}
	}
	return nil
}

func (s *Store) Delete(ip string) error {
	if s == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if s.rdb != nil {
		_ = s.rdb.Del(ctx, "ban:"+ip).Err()
	}
	if s.coll != nil {
		_, _ = s.coll.DeleteOne(ctx, bson.M{"ip": ip})
	}
	return nil
}

func (s *Store) List() ([]Ban, error) {
	if s == nil {
		return nil, nil
	}
	out := []Ban{}
	if s.rdb != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		iter := s.rdb.Scan(ctx, 0, "ban:*", 100).Iterator()
		for iter.Next(ctx) {
			key := iter.Val()
			data, err := s.rdb.Get(ctx, key).Bytes()
			if err != nil {
				continue
			}
			var b Ban
			if json.Unmarshal(data, &b) != nil {
				continue
			}
			out = append(out, b)
		}
		if err := iter.Err(); err != nil {
			return nil, err
		}
	}
	if s.coll != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		cur, err := s.coll.Find(ctx, bson.M{})
		if err != nil {
			return out, nil
		}
		defer cur.Close(ctx)
		exists := map[string]bool{}
		for _, b := range out {
			exists[b.IP] = true
		}
		for cur.Next(ctx) {
			var b Ban
			if cur.Decode(&b) != nil {
				continue
			}
			if exists[b.IP] {
				continue
			}
			out = append(out, b)
		}
	}
	return out, nil
}

func (s *Store) Get(ip string) (Ban, bool, error) {
	var out Ban
	if s == nil || ip == "" {
		return out, false, nil
	}
	if s.rdb != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		data, err := s.rdb.Get(ctx, "ban:"+ip).Bytes()
		if err == nil {
			if json.Unmarshal(data, &out) == nil {
				return out, true, nil
			}
		}
	}
	if s.coll != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		err := s.coll.FindOne(ctx, bson.M{"ip": ip}).Decode(&out)
		if err != nil {
			if err == mongo.ErrNoDocuments {
				return Ban{}, false, nil
			}
			return Ban{}, false, err
		}
		return out, true, nil
	}
	return Ban{}, false, nil
}

func (s *Store) DeleteAll() error {
	if s == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if s.rdb != nil {
		iter := s.rdb.Scan(ctx, 0, "ban:*", 100).Iterator()
		for iter.Next(ctx) {
			key := iter.Val()
			_ = s.rdb.Del(ctx, key).Err()
		}
		if err := iter.Err(); err != nil {
			return err
		}
	}
	if s.coll != nil {
		_, err := s.coll.DeleteMany(ctx, bson.M{})
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) PurgeExpired() error {
	return nil
}

func (s *Store) RecordIP(ip string) {
	if s == nil || s.ipColl == nil || ip == "" {
		return
	}
	now := time.Now().Unix()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	update := bson.M{
		"$set": bson.M{
			"ip":        ip,
			"last_seen": now,
		},
		"$setOnInsert": bson.M{
			"first_seen": now,
		},
		"$inc": bson.M{
			"count": 1,
		},
	}
	_, _ = s.ipColl.UpdateOne(ctx, bson.M{"ip": ip}, update, options.Update().SetUpsert(true))
}

func (s *Store) BumpIPRisk(ip string, delta int64) {
	if s == nil || s.rdb == nil || ip == "" || delta == 0 {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	key := "risk:ip:" + ip
	_ = s.rdb.IncrBy(ctx, key, delta).Err()
	_ = s.rdb.Expire(ctx, key, 24*time.Hour).Err()
}

func (s *Store) GetIPRisk(ip string) int64 {
	if s == nil || s.rdb == nil || ip == "" {
		return 0
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	v, err := s.rdb.Get(ctx, "risk:ip:"+ip).Int64()
	if err != nil {
		return 0
	}
	return v
}

func (s *Store) AllowRateIP(ip string, limit int64, windowSeconds int) bool {
	if s == nil || s.rdb == nil || ip == "" || limit <= 0 || windowSeconds <= 0 {
		return true
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	key := "ip:" + ip + ":" + strconv.Itoa(windowSeconds) + "s"
	v, err := s.rdb.Incr(ctx, key).Result()
	if err != nil {
		return true
	}
	if v == 1 {
		_ = s.rdb.Expire(ctx, key, time.Duration(windowSeconds)*time.Second).Err()
	}
	if v > limit {
		return false
	}
	return true
}

func (s *Store) MarkTempBlocked(ip string, ttl time.Duration) {
	if s == nil || s.rdb == nil || ip == "" {
		return
	}
	if ttl <= 0 {
		ttl = time.Hour
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = s.rdb.Set(ctx, "blocked:"+ip, "1", ttl).Err()
}

func (s *Store) IsTempBlocked(ip string) bool {
	if s == nil || s.rdb == nil || ip == "" {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	n, err := s.rdb.Exists(ctx, "blocked:"+ip).Result()
	if err != nil {
		return false
	}
	return n > 0
}

func (s *Store) MarkCaptcha(ip string, ttl time.Duration) {
	if s == nil || s.rdb == nil || ip == "" {
		return
	}
	if ttl <= 0 {
		ttl = 30 * time.Minute
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = s.rdb.Set(ctx, "captcha:"+ip, "1", ttl).Err()
}

func (s *Store) HasCaptcha(ip string) bool {
	if s == nil || s.rdb == nil || ip == "" {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	n, err := s.rdb.Exists(ctx, "captcha:"+ip).Result()
	if err != nil {
		return false
	}
	return n > 0
}

func (s *Store) EnqueueIPLog(v any) {
	if s == nil || s.rdb == nil || v == nil {
		return
	}
	b, err := json.Marshal(v)
	if err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = s.rdb.RPush(ctx, "queue:ip_logs", b).Err()
}

func (s *Store) SetMeta(ip string, m Meta, ttl time.Duration) {
	if s == nil || s.rdb == nil || ip == "" {
		return
	}
	now := time.Now().Unix()
	if m.IP == "" {
		m.IP = ip
	}
	if m.UpdatedAt == 0 {
		m.UpdatedAt = now
	}
	if ttl <= 0 {
		ttl = 6 * time.Hour
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	key := "meta:" + ip
	fields := map[string]any{
		"ip":           m.IP,
		"country":      m.Country,
		"country_code": m.CountryCode,
		"asn":          m.ASN,
		"org":          m.Org,
		"risk":         m.Risk,
		"updated_at":   m.UpdatedAt,
	}
	_ = s.rdb.HSet(ctx, key, fields).Err()
	_ = s.rdb.Expire(ctx, key, ttl).Err()
}

// GetMeta returns cached metadata for an IP if present.
// This is used as a secondary source for geo/ASN when the live
// geo provider lookup fails at request time.
func (s *Store) GetMeta(ip string) (Meta, bool) {
	var out Meta
	if s == nil || s.rdb == nil || ip == "" {
		return out, false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	key := "meta:" + ip
	m, err := s.rdb.HGetAll(ctx, key).Result()
	if err != nil || len(m) == 0 {
		return out, false
	}
	out.IP = m["ip"]
	if out.IP == "" {
		out.IP = ip
	}
	out.Country = m["country"]
	out.CountryCode = m["country_code"]
	out.ASN = m["asn"]
	out.Org = m["org"]
	if v, err := strconv.ParseInt(m["risk"], 10, 64); err == nil {
		out.Risk = v
	}
	if v, err := strconv.ParseInt(m["updated_at"], 10, 64); err == nil {
		out.UpdatedAt = v
	}
	return out, true
}

func (s *Store) moveForeverToMongoLoop() {
	t := time.NewTicker(10 * time.Minute)
	defer t.Stop()
	for range t.C {
		_ = s.moveForeverToMongo()
	}
}

func (s *Store) moveForeverToMongo() error {
	if s == nil || s.rdb == nil || s.coll == nil {
		return nil
	}
	ctx := context.Background()
	iter := s.rdb.Scan(ctx, 0, "ban:*", 100).Iterator()
	now := time.Now().Unix()
	cutoff := now - 3600
	for iter.Next(ctx) {
		key := iter.Val()
		data, err := s.rdb.Get(ctx, key).Bytes()
		if err != nil {
			continue
		}
		var b Ban
		if json.Unmarshal(data, &b) != nil {
			continue
		}
		if !b.Permanent {
			continue
		}
		if b.CreatedAt >= cutoff {
			continue
		}
		_, err = s.coll.UpdateOne(ctx, bson.M{"ip": b.IP}, bson.M{"$set": b}, options.Update().SetUpsert(true))
		if err != nil {
			continue
		}
		_ = s.rdb.Del(ctx, key).Err()
	}
	return iter.Err()
}

// ResetStat represents aggregated information about TCP connection resets
// performed against a given IP.
type ResetStat struct {
	IP      string `json:"ip"`
	Count   int64  `json:"count"`
	FirstAt int64  `json:"first_at"`
	LastAt  int64  `json:"last_at"`
}

// RecordReset records a TCP reset for the given IP. This uses Redis only and
// does not touch MongoDB. It keeps a bounded time window via key TTLs.
func (s *Store) RecordReset(ip string) {
	if s == nil || s.rdb == nil || ip == "" {
		return
	}
	now := time.Now().Unix()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	key := "rst:" + ip
	pipe := s.rdb.TxPipeline()
	pipe.HSet(ctx, key, map[string]any{
		"ip":      ip,
		"last_at": now,
	})
	pipe.HSetNX(ctx, key, "first_at", now)
	pipe.HIncrBy(ctx, key, "count", 1)
	pipe.SAdd(ctx, "rst:ips", ip)
	// Keep resets for 24h; dashboard cares about recent behaviour.
	pipe.Expire(ctx, key, 24*time.Hour)
	pipe.Expire(ctx, "rst:ips", 24*time.Hour)
	_, _ = pipe.Exec(ctx)
}

// GetReset returns aggregated reset stats for a single IP.
func (s *Store) GetReset(ip string) (ResetStat, bool, error) {
	var out ResetStat
	if s == nil || s.rdb == nil || ip == "" {
		return out, false, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	key := "rst:" + ip
	m, err := s.rdb.HGetAll(ctx, key).Result()
	if err != nil || len(m) == 0 {
		return out, false, nil
	}
	out.IP = m["ip"]
	if out.IP == "" {
		out.IP = ip
	}
	if v, err := strconv.ParseInt(m["count"], 10, 64); err == nil {
		out.Count = v
	}
	if v, err := strconv.ParseInt(m["first_at"], 10, 64); err == nil {
		out.FirstAt = v
	}
	if v, err := strconv.ParseInt(m["last_at"], 10, 64); err == nil {
		out.LastAt = v
	}
	return out, true, nil
}

// ListResets returns aggregated reset stats for all IPs that have seen
// at least one reset within the retention window, sorted by LastAt desc.
func (s *Store) ListResets(limit int) ([]ResetStat, error) {
	if s == nil || s.rdb == nil {
		return nil, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	ips, err := s.rdb.SMembers(ctx, "rst:ips").Result()
	if err != nil {
		return nil, err
	}
	out := make([]ResetStat, 0, len(ips))
	for _, ip := range ips {
		st, ok, err := s.GetReset(ip)
		if err != nil {
			return nil, err
		}
		if !ok {
			continue
		}
		out = append(out, st)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].LastAt > out[j].LastAt
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

// ClearReset deletes reset statistics for a single IP.
func (s *Store) ClearReset(ip string) error {
	if s == nil || s.rdb == nil || ip == "" {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	key := "rst:" + ip
	_ = s.rdb.Del(ctx, key).Err()
	_ = s.rdb.SRem(ctx, "rst:ips", ip).Err()
	return nil
}

// ClearAllResets deletes all tracked reset statistics.
func (s *Store) ClearAllResets() error {
	if s == nil || s.rdb == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ips, err := s.rdb.SMembers(ctx, "rst:ips").Result()
	if err != nil {
		return err
	}
	if len(ips) > 0 {
		keys := make([]string, 0, len(ips)+1)
		for _, ip := range ips {
			keys = append(keys, "rst:"+ip)
		}
		keys = append(keys, "rst:ips")
		_ = s.rdb.Del(ctx, keys...).Err()
	} else {
		_ = s.rdb.Del(ctx, "rst:ips").Err()
	}
	return nil
}