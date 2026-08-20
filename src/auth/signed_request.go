package auth

import (
	"errors"
	"strconv"
	"sync"
	"time"
)

const SignedRequestWindow = 5 * time.Minute

func VerifySignedRequest(pubKeyPEM string, fields []string, timestampMs, nonce, signatureB64 string) error {
	if timestampMs == "" || nonce == "" || signatureB64 == "" {
		return errors.New("timestamp, nonce and signature are required")
	}
	ts, err := strconv.ParseInt(timestampMs, 10, 64)
	if err != nil {
		return errors.New("invalid timestamp")
	}
	diff := time.Now().UnixMilli() - ts
	if diff < 0 {
		diff = -diff
	}
	if diff > SignedRequestWindow.Milliseconds() {
		return errors.New("timestamp outside allowed window")
	}

	all := append(append([]string{}, fields...), timestampMs, nonce)
	digest := MessageDigest(all...)
	if err := VerifyMessageSignature(pubKeyPEM, digest, signatureB64); err != nil {
		return errors.New("signature verification failed")
	}
	return nil
}


var (
	nonceMu   sync.Mutex
	nonceSeen = map[string]map[string]time.Time{}
)

const nonceMax = 1000

const nonceMaxPerUser = 1000

func CheckNonce(userID, nonce string) bool {
	nonceMu.Lock()
	defer nonceMu.Unlock()

	now := time.Now()
	if len(nonceSeen) >= nonceMax {
		for u, m := range nonceSeen {
			for n, t := range m {
				if now.Sub(t) > SignedRequestWindow {
					delete(m, n)
				}
			}
			if len(m) == 0 {
				delete(nonceSeen, u)
			}
		}
	}

	m, ok := nonceSeen[userID]
	if !ok {
		m = map[string]time.Time{}
		nonceSeen[userID] = m
	}

	if len(m) >= nonceMaxPerUser {
		for n, t := range m {
			if now.Sub(t) > SignedRequestWindow {
				delete(m, n)
			}
		}
	}
	if len(m) >= nonceMaxPerUser {
		for n := range m {
			delete(m, n)
			break
		}
	}

	if t, dup := m[nonce]; dup && now.Sub(t) < SignedRequestWindow {
		return true
	}
	m[nonce] = now
	return false
}
