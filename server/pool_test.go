package main

import (
	"fmt"
	"testing"
	"time"
)

// newTestPool creates a fresh CredentialPool for testing.
func newTestPool() *CredentialPool {
	return &CredentialPool{
		activeCalls: make(map[string]*ActiveCall),
		assignments: make(map[string]string),
	}
}

// addTestCall is a helper that adds a call with sensible defaults.
func addTestCall(p *CredentialPool, accountID, username, password, address string) {
	p.AddCall(accountID, "account-"+accountID, username, password, address, time.Now().Add(2*time.Hour))
}

// ─── TestPoolAssignment ───

func TestPoolAssignment(t *testing.T) {
	p := newTestPool()
	addTestCall(p, "acc1", "user1", "pass1", "1.2.3.4:3478")

	u, pw, addr, ok := p.GetOrAssignCreds("client-a")
	if !ok {
		t.Fatal("expected ok=true, got false")
	}
	if u != "user1" || pw != "pass1" || addr != "1.2.3.4:3478" {
		t.Fatalf("unexpected creds: %s / %s / %s", u, pw, addr)
	}

	// Calling again returns the same assignment
	u2, pw2, addr2, ok2 := p.GetOrAssignCreds("client-a")
	if !ok2 {
		t.Fatal("expected ok=true on second call")
	}
	if u2 != u || pw2 != pw || addr2 != addr {
		t.Fatal("expected same creds on second call")
	}
}

// ─── TestPoolReassignment ───

func TestPoolReassignment(t *testing.T) {
	p := newTestPool()
	addTestCall(p, "acc1", "user1", "pass1", "1.2.3.4:3478")

	// Assign client to acc1
	_, _, _, ok := p.GetOrAssignCreds("client-a")
	if !ok {
		t.Fatal("expected assignment to succeed")
	}

	// End acc1's call
	p.EndCall("acc1")

	// Add a new call
	addTestCall(p, "acc2", "user2", "pass2", "5.6.7.8:3478")

	// Client should be reassigned to acc2
	u, pw, addr, ok := p.GetOrAssignCreds("client-a")
	if !ok {
		t.Fatal("expected reassignment to succeed")
	}
	if u != "user2" || pw != "pass2" || addr != "5.6.7.8:3478" {
		t.Fatalf("expected acc2 creds, got: %s / %s / %s", u, pw, addr)
	}
}

// ─── TestPoolRelease ───

func TestPoolRelease(t *testing.T) {
	p := newTestPool()
	addTestCall(p, "acc1", "user1", "pass1", "1.2.3.4:3478")

	p.GetOrAssignCreds("client-a")
	p.GetOrAssignCreds("client-b")

	p.ReleaseClient("client-a")

	// Verify the pool stats reflect the release
	calls, assigned, total := p.Stats()
	if calls != 1 {
		t.Fatalf("expected 1 active call, got %d", calls)
	}
	if assigned != 1 {
		t.Fatalf("expected 1 assigned client, got %d", assigned)
	}
	if total != 1 {
		t.Fatalf("expected 1 total client in calls, got %d", total)
	}

	// Releasing a non-existent client is a no-op
	p.ReleaseClient("no-such-client")
	_, assigned2, _ := p.Stats()
	if assigned2 != 1 {
		t.Fatalf("expected 1 assigned after no-op release, got %d", assigned2)
	}
}

// ─── TestPoolEndCall ───

func TestPoolEndCall(t *testing.T) {
	p := newTestPool()
	addTestCall(p, "acc1", "user1", "pass1", "1.2.3.4:3478")

	p.GetOrAssignCreds("client-a")
	p.GetOrAssignCreds("client-b")

	orphaned := p.EndCall("acc1")
	if len(orphaned) != 2 {
		t.Fatalf("expected 2 orphaned clients, got %d", len(orphaned))
	}

	// Verify orphaned names
	names := make(map[string]bool)
	for _, n := range orphaned {
		names[n] = true
	}
	if !names["client-a"] || !names["client-b"] {
		t.Fatalf("expected client-a and client-b in orphaned, got %v", orphaned)
	}

	// Pool should be empty now
	calls, assigned, total := p.Stats()
	if calls != 0 || assigned != 0 || total != 0 {
		t.Fatalf("expected empty pool, got calls=%d assigned=%d total=%d", calls, assigned, total)
	}

	// Ending a non-existent call returns nil
	orphaned2 := p.EndCall("no-such-acc")
	if orphaned2 != nil {
		t.Fatalf("expected nil for non-existent call, got %v", orphaned2)
	}
}

// ─── TestPoolGetAnyCreds ───

func TestPoolGetAnyCreds(t *testing.T) {
	p := newTestPool()

	// No calls — should fail
	_, _, _, ok := p.GetAnyCreds()
	if ok {
		t.Fatal("expected ok=false with no active calls")
	}

	addTestCall(p, "acc1", "user1", "pass1", "1.2.3.4:3478")

	u, pw, addr, ok := p.GetAnyCreds()
	if !ok {
		t.Fatal("expected ok=true with active call")
	}
	if u != "user1" || pw != "pass1" || addr != "1.2.3.4:3478" {
		t.Fatalf("unexpected creds from GetAnyCreds: %s / %s / %s", u, pw, addr)
	}
}

// ─── TestPoolStats ───

func TestPoolStats(t *testing.T) {
	p := newTestPool()

	calls, assigned, total := p.Stats()
	if calls != 0 || assigned != 0 || total != 0 {
		t.Fatalf("expected all zeros, got %d/%d/%d", calls, assigned, total)
	}

	addTestCall(p, "acc1", "user1", "pass1", "1.2.3.4:3478")
	addTestCall(p, "acc2", "user2", "pass2", "5.6.7.8:3478")

	calls, assigned, total = p.Stats()
	if calls != 2 {
		t.Fatalf("expected 2 calls, got %d", calls)
	}
	if assigned != 0 || total != 0 {
		t.Fatalf("expected 0 clients, got assigned=%d total=%d", assigned, total)
	}

	p.GetOrAssignCreds("client-a")
	p.GetOrAssignCreds("client-b")
	p.GetOrAssignCreds("client-c")

	calls, assigned, total = p.Stats()
	if calls != 2 {
		t.Fatalf("expected 2 calls, got %d", calls)
	}
	if assigned != 3 {
		t.Fatalf("expected 3 assigned, got %d", assigned)
	}
	if total != 3 {
		t.Fatalf("expected 3 total, got %d", total)
	}
}

// ─── TestPoolNoActiveCalls ───

func TestPoolNoActiveCalls(t *testing.T) {
	p := newTestPool()

	_, _, _, ok := p.GetOrAssignCreds("client-a")
	if ok {
		t.Fatal("expected ok=false with no active calls")
	}
}

// ─── TestPoolMultipleClients ───

func TestPoolMultipleClients(t *testing.T) {
	p := newTestPool()
	addTestCall(p, "acc1", "user1", "pass1", "1.2.3.4:3478")

	// All clients should go to the only available call
	for _, name := range []string{"c1", "c2", "c3", "c4", "c5"} {
		u, _, _, ok := p.GetOrAssignCreds(name)
		if !ok {
			t.Fatalf("expected ok=true for %s", name)
		}
		if u != "user1" {
			t.Fatalf("expected user1 for %s, got %s", name, u)
		}
	}

	_, _, total := p.Stats()
	if total != 5 {
		t.Fatalf("expected 5 total clients, got %d", total)
	}
}

// ─── TestPoolLeastLoaded ───

func TestPoolLeastLoaded(t *testing.T) {
	p := newTestPool()
	addTestCall(p, "acc1", "user1", "pass1", "1.2.3.4:3478")
	addTestCall(p, "acc2", "user2", "pass2", "5.6.7.8:3478")

	// First two clients should go to different calls (least-loaded)
	u1, _, _, _ := p.GetOrAssignCreds("client-a")
	u2, _, _, _ := p.GetOrAssignCreds("client-b")

	if u1 == u2 {
		t.Fatalf("expected clients on different calls, both got %s", u1)
	}

	// Third client should go to whichever has fewer (both have 1, so either is fine)
	p.GetOrAssignCreds("client-c")

	// Add a third call with 0 clients — next client must go there
	addTestCall(p, "acc3", "user3", "pass3", "9.10.11.12:3478")

	u4, _, _, ok := p.GetOrAssignCreds("client-d")
	if !ok {
		t.Fatal("expected ok=true")
	}
	if u4 != "user3" {
		t.Fatalf("expected client-d on acc3 (least loaded, 0 clients), got %s", u4)
	}
}

// ─── TestPoolAddCallOverwrite ───

func TestPoolAddCallOverwrite(t *testing.T) {
	p := newTestPool()
	addTestCall(p, "acc1", "user1", "pass1", "1.2.3.4:3478")
	p.GetOrAssignCreds("client-a")

	// Overwrite acc1 with new creds
	addTestCall(p, "acc1", "user1-new", "pass1-new", "10.0.0.1:3478")

	// Existing assignment should still point to acc1, now with new creds
	u, pw, addr, ok := p.GetOrAssignCreds("client-a")
	if !ok {
		t.Fatal("expected ok=true")
	}
	if u != "user1-new" || pw != "pass1-new" || addr != "10.0.0.1:3478" {
		t.Fatalf("expected updated creds, got %s / %s / %s", u, pw, addr)
	}
}

// ─── TestPoolActiveCallsList ───

func TestPoolActiveCallsList(t *testing.T) {
	p := newTestPool()

	list := p.ActiveCallsList()
	if list != nil && len(list) != 0 {
		t.Fatalf("expected empty list, got %d items", len(list))
	}

	p.AddCall("acc1", "myaccount", "user1", "pass1", "1.2.3.4:3478", time.Now().Add(2*time.Hour))
	p.GetOrAssignCreds("client-a")

	list = p.ActiveCallsList()
	if len(list) != 1 {
		t.Fatalf("expected 1 item, got %d", len(list))
	}

	item := list[0]
	if item["account_id"] != "acc1" {
		t.Errorf("expected account_id=acc1, got %v", item["account_id"])
	}
	if item["account_name"] != "myaccount" {
		t.Errorf("expected account_name=myaccount, got %v", item["account_name"])
	}
	if item["client_count"] != 1 {
		t.Errorf("expected client_count=1, got %v", item["client_count"])
	}
}

// ─── TestPoolConcurrentAccess ───

func TestPoolConcurrentAccess(t *testing.T) {
	p := newTestPool()
	addTestCall(p, "acc1", "user1", "pass1", "1.2.3.4:3478")

	done := make(chan bool, 20)
	for i := 0; i < 10; i++ {
		go func(id int) {
			name := fmt.Sprintf("client-%d", id)
			p.GetOrAssignCreds(name)
			done <- true
		}(i)
	}
	for i := 0; i < 10; i++ {
		go func(id int) {
			name := fmt.Sprintf("client-%d", id)
			p.ReleaseClient(name)
			done <- true
		}(i)
	}
	for i := 0; i < 20; i++ {
		<-done
	}

	// Just verify no panic / deadlock occurred — stats should be consistent
	calls, _, _ := p.Stats()
	if calls != 1 {
		t.Fatalf("expected 1 active call, got %d", calls)
	}
}
