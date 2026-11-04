// Package hid enumerates native HID endpoints and exchanges fixed-size Input
// and Output reports. Endpoint IDs address interfaces or collections, not
// physical tokens. A write completion confirms native delivery, not execution
// of a device command.
//
// Native operations retain resource ownership until completion, even when a
// caller's context expires. All Native values share limits of 64 connections
// (including opening and retiring connections), one enumeration, 64 queued
// input reports per connection, 64 KiB descriptors, 4096-byte reports, and a
// 64 MiB buffer reservation budget (768 KiB per connection and 16 MiB per
// enumeration). Inventory is bounded to 128 native devices and 1024 endpoints. A stuck native operation keeps its reserved
// resources quarantined; constructing another Native cannot bypass the limits.
package hid
