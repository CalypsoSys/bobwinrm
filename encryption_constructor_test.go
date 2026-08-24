package winrm

import "testing"

func TestNewEncryptionProtocols(t *testing.T) {
	ntlm, err := NewEncryption("ntlm")
	if err != nil {
		t.Fatal(err)
	}
	if ntlm.protocol != "ntlm" || ntlm.kerberos != nil {
		t.Fatalf("unexpected NTLM transport: %#v", ntlm)
	}

	kerberos, err := NewEncryption("kerberos")
	if err != nil {
		t.Fatal(err)
	}
	if kerberos.protocol != "kerberos" || kerberos.kerberos == nil {
		t.Fatalf("unexpected Kerberos transport: %#v", kerberos)
	}

	configured, err := NewEncryptionWithSettings("kerberos", &Settings{
		WinRMUsername:          "user",
		WinRMPassword:          "password",
		WinRMHost:              "server.example.com",
		KrbRealm:               "EXAMPLE.COM",
		KrbConfig:              "/etc/krb5.conf",
		KrbSpn:                 "HTTP/server.example.com",
		WinRMMessageEncryption: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if configured.kerberos.Username != "user" || !configured.kerberos.MessageEncryption {
		t.Fatalf("Kerberos settings were not applied: %#v", configured.kerberos)
	}

	if _, err := NewEncryption("credssp"); err == nil {
		t.Fatal("CredSSP unexpectedly supported without a CredSSP authentication transport")
	}
}
