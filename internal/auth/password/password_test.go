package password

import "testing"

func TestHashVerifyRoundTrip(t *testing.T) {
	h, err := Hash("hunter22")
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	ok, err := Verify(h, "hunter22")
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !ok {
		t.Fatal("expected verify to succeed")
	}
}

func TestVerifyWrongPassword(t *testing.T) {
	h, err := Hash("hunter22")
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	ok, err := Verify(h, "hunter23")
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if ok {
		t.Fatal("expected verify to fail")
	}
}

func TestVerifyMalformedNoPanic(t *testing.T) {
	cases := []string{
		"",
		"not-a-hash",
		"$argon2id$v=19$m=65536,t=1,p=4$!!!!$!!!!",
		"$argon2i$v=19$m=65536,t=1,p=4$YWJjZA$YWJjZA",
		"$argon2id$v=19$m=bad,t=1,p=4$YWJjZA$YWJjZA",
		"$argon2id$v=bad$m=65536,t=1,p=4$YWJjZA$YWJjZA",
	}
	for _, s := range cases {
		ok, err := Verify(s, "anything")
		if err == nil {
			t.Errorf("expected error for %q", s)
		}
		if ok {
			t.Errorf("expected !ok for %q", s)
		}
	}
}

func TestCheckNew(t *testing.T) {
	cases := map[string]bool{
		"":                false,
		"fourteen-chars":  false,
		"fifteen-chars!!": true,
		"ééééééééééééééé": true, // 15 runes, 30 bytes
		"éééééééééééééé":  false,
	}
	for in, ok := range cases {
		if err := CheckNew(in); (err == nil) != ok {
			t.Errorf("CheckNew(%q) err=%v, want ok=%v", in, err, ok)
		}
	}
}
