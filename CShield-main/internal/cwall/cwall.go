package cwall

// Firewall is now a no-op wrapper kept only for compatibility.
// All real-time blocking is done via per-connection TCP RST in main.go/core.Gate.

import "time"

type Firewall struct{}

func New() *Firewall                    { return &Firewall{} }
func (f *Firewall) Close()              {}
func (f *Firewall) DropShort(ip string, dur time.Duration) {}
func (f *Firewall) DropForever(ip string)                  {}
func (f *Firewall) Unban(ip string)                        {}
func (f *Firewall) IsBanned(ip string) bool                { return false }