package nftdesk

import (
	"fmt"

	"github.com/nickgarlis/nftdesk/models"

	"github.com/google/nftables"
)

type NftDesk struct {
	conn *nftables.Conn
}

func New() (*NftDesk, error) {
	conn, err := nftables.New()
	if err != nil {
		return nil, fmt.Errorf("failed to create nftables connection: %w", err)
	}

	return &NftDesk{conn: conn}, nil
}

func (n *NftDesk) HasTable(name string) bool {
	table, _ := n.conn.ListTable(name)
	return table != nil
}

func (n *NftDesk) HasTableOfFamily(name string, family nftables.TableFamily) bool {
	table, _ := n.conn.ListTableOfFamily(name, family)
	return table != nil
}

// Get a table by name. Returns an error if the table does not exist.
func (n *NftDesk) GetTable(name string) (*models.Table, error) {
	table, err := n.conn.ListTable(name)
	if err != nil {
		return nil, fmt.Errorf("failed to list table %s: %v", name, err)
	}

	return models.NewTable(n.conn, table), nil
}

// Get a table by name and family. Returns an error if the table does not exist.
func (n *NftDesk) GetTableOfFamily(name string, family nftables.TableFamily) (*models.Table, error) {
	table, err := n.conn.ListTableOfFamily(name, family)
	if err != nil {
		return nil, fmt.Errorf("failed to list table %s: %v", name, err)
	}

	return models.NewTable(n.conn, table), nil
}

func (n *NftDesk) AddTable(name string, family models.TableFamily) *models.Table {
	tableObj := n.conn.AddTable(&nftables.Table{
		Name:   name,
		Family: family,
	})

	return models.NewTable(n.conn, tableObj)
}

func (n *NftDesk) Flush() error {
	err := n.conn.Flush()
	if err != nil {
		return fmt.Errorf("failed to flush nftables: %w", err)
	}
	return nil
}

func (n *NftDesk) FlushRuleset() {
	n.conn.FlushRuleset()
}
