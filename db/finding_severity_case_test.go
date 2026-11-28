package db

import (
	"context"
	"testing"

	"github.com/Autumn-27/artex/notify"
)

// A model can write the severity of report_finding as "High" or " critical ".
// The finding must be stored with the canonical lowercase level, or the
// severity counters and every min_severity notification channel skip it.
func TestRecordFindingStoresCanonicalSeverity(t *testing.T) {
	d := notifyTestDB(t)
	ctx := context.Background()
	ch := newTestChannel(t, d, notify.KindDingTalk, NotifyModeRealtime, `{"min_severity":"high"}`)

	tk, err := d.CreateTask("severity case test", "goal", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(tk.ID) })
	f, err := d.Exploration(tk.ExplorationID).RecordFinding(ctx, RecordFindingInput{
		TaskID: tk.ID, Worker: "test", VulnClass: "SQL injection", Name: "severity case",
		Severity: " High ", Summary: "summary",
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = d.Exec(`DELETE FROM notification_events WHERE finding_id=$1`, f.FindingID)
		_, _ = d.DeleteFinding(f.FindingID)
	})

	var severity string
	if err := d.QueryRow(`SELECT severity FROM findings WHERE id=$1`, f.FindingID).Scan(&severity); err != nil {
		t.Fatal(err)
	}
	if severity != SeverityHigh {
		t.Fatalf("stored severity = %q, want %q", severity, SeverityHigh)
	}
	if _, _, err := d.FanOutPendingEvents(ctx, 1000); err != nil {
		t.Fatal(err)
	}
	var deliveries int
	if err := d.QueryRow(`SELECT count(*) FROM notification_deliveries dl JOIN notification_events ev ON ev.id=dl.event_id
WHERE dl.channel_id=$1 AND ev.finding_id=$2`, ch.ID, f.FindingID).Scan(&deliveries); err != nil {
		t.Fatal(err)
	}
	if deliveries != 1 {
		t.Fatalf("a high finding must reach the min_severity=high channel, got %d deliveries", deliveries)
	}
}
