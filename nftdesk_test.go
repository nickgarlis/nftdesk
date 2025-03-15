package nftdesk

import (
	"net"
	"os"
	"testing"
	"time"

	"github.com/nickgarlis/nftdesk/expr"
	"github.com/nickgarlis/nftdesk/models"
)

var d *NftDesk
var err error

func TestMain(m *testing.M) {
	// Setup
	d, err = NewNftDesk()
	if err != nil {
		panic(err)
	}
	d.FlushRuleset()
	d.Flush()

	code := m.Run()

	// Teardown
	d.FlushRuleset()
	d.Flush()
	os.Exit(code)
}

func TestBasic(t *testing.T) {
	table := d.AddTable("test-table", models.TableFamilyIPv4)

	chain := table.AddChain("test-chain")

	_, err := chain.AddRule(
		expr.CtStateExpr().In(expr.CtStateESTABLISHED, expr.CtStateRELATED),
		expr.VerdictExpr().OfKindAccept(),
	)
	if err != nil {
		t.Error(err)
	}

	_, err = chain.AddRule(
		expr.IfaceMeta().OfKindInput().Eq("lo"),
		expr.IPv4Payload().Eq(net.IPv4(127, 0, 0, 1)),
		expr.VerdictExpr().OfKindAccept(),
	)
	if err != nil {
		t.Error(err)
	}

	set, err := table.AddIPAddrSet("test-set", []*models.IPAddrSetElement{
		{IP: "5.5.5.5/30", Timeout: time.Hour * 2, Comment: "test-element"},
	})

	if err != nil {
		t.Error(err)
	}

	_, err = chain.AddRule(
		expr.IPv4Payload().InSet(set.ID(), set.Name()),
		expr.VerdictExpr().OfKindAccept(),
	)
	if err != nil {
		t.Error(err)
	}

	_, err = chain.AddRule(
		expr.VerdictExpr().OfKindDrop(),
	)
	if err != nil {
		t.Error(err)
	}

	err = d.Flush()
	if err != nil {
		t.Error(err)
	}

	d.AddTable("test-table-ipv6", models.TableFamilyIPv6)
	err = d.Flush()
	if err != nil {
		t.Error(err)
	}
}
