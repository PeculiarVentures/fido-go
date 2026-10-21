package usb

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/PeculiarVentures/fido-go/pkg/transport"
)

func awaitHIDResult(t *testing.T, result <-chan error) error {
	t.Helper()
	select {
	case err := <-result:
		return err
	case <-time.After(2 * time.Second):
		t.Fatal("exchange did not finish")
		return nil
	}
}

func awaitHIDRead(t *testing.T, dev *fakeHIDDevice) {
	t.Helper()
	select {
	case <-dev.readStarted:
	case <-time.After(time.Second):
		t.Fatal("exchange did not start reading")
	}
}

func TestHIDSessionCancelOrDeadlineInterruptsNativeIO(t *testing.T) {
	t.Parallel()
	for _, operation := range []string{"read", "write"} {
		for _, deadline := range []bool{false, true} {
			t.Run(operation+map[bool]string{false: "/cancel", true: "/deadline"}[deadline], func(t *testing.T) {
				session, dev := newTestHIDSession(t)
				started := make(chan struct{})
				release := make(chan struct{})
				var releaseOnce sync.Once
				releaseWrite := func() { releaseOnce.Do(func() { close(release) }) }
				t.Cleanup(releaseWrite)
				if operation == "write" {
					dev.onWrite = func([]byte) error {
						close(started)
						<-release
						return errors.New("write interrupted")
					}
				}
				var ctx context.Context
				var cancel context.CancelFunc
				want := context.Canceled
				if deadline {
					ctx, cancel = context.WithTimeout(context.Background(), 200*time.Millisecond)
					want = context.DeadlineExceeded
				} else {
					ctx, cancel = context.WithCancel(context.Background())
				}
				defer cancel()
				result := make(chan error, 1)
				go func() { _, err := session.ExchangeHID(ctx, 0x42, nil); result <- err }()
				if operation == "read" {
					awaitHIDRead(t, dev)
				} else {
					select {
					case <-started:
					case <-time.After(time.Second):
						t.Fatal("write did not start")
					}
				}
				if !deadline {
					cancel()
				}
				if err := awaitHIDResult(t, result); !errors.Is(err, want) {
					t.Fatalf("error = %v, want %v", err, want)
				}
				if _, err := session.Exchange(context.Background(), []byte{4}); !errors.Is(err, transport.ErrDisconnected) {
					t.Fatalf("ordinary exchange after cancellation = %v", err)
				}
				if operation == "write" {
					select {
					case <-dev.closed:
						t.Fatal("cancellation freed a handle still used by native Write")
					default:
					}
				}
				releaseWrite()
				if err := session.Close(); err != nil {
					t.Fatal(err)
				}
				select {
				case <-dev.closed:
				default:
					t.Fatal("native handle was not cleaned up after I/O returned")
				}
			})
		}
	}
}

func TestHIDSessionSerializesOrdinaryAndExplicitExchangesWithCancelableWait(t *testing.T) {
	t.Parallel()
	for _, vendorFirst := range []bool{false, true} {
		t.Run(map[bool]string{false: "ordinary first", true: "vendor first"}[vendorFirst], func(t *testing.T) {
			session, dev := newTestHIDSession(t)
			first, second := make(chan error, 1), make(chan error, 1)
			call := func(ctx context.Context, vendor bool) ([]byte, error) {
				if vendor {
					return session.ExchangeHID(ctx, 0x42, []byte{0})
				}
				return session.Exchange(ctx, []byte{4})
			}
			go func() {
				got, err := call(context.Background(), vendorFirst)
				if err == nil && !bytes.Equal(got, []byte{0xaa}) {
					err = errors.New("first exchange got another command's response")
				}
				first <- err
			}()
			awaitHIDRead(t, dev)
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
			defer cancel()
			go func() { _, err := call(ctx, !vendorFirst); second <- err }()
			if err := awaitHIDResult(t, second); !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("queued call = %v", err)
			}
			if len(dev.writtenPackets()) != 1 {
				t.Fatal("queued request wrote during another transaction")
			}
			select {
			case <-dev.closed:
				t.Fatal("canceling a queued exchange closed another caller's connection")
			default:
			}
			go func() {
				got, err := call(context.Background(), !vendorFirst)
				if err == nil && !bytes.Equal(got, []byte{0xbb}) {
					err = errors.New("second exchange got another command's response")
				}
				second <- err
			}()
			firstCommand, secondCommand := byte(hidCommandCBOR), byte(0xc2)
			if vendorFirst {
				firstCommand, secondCommand = secondCommand, firstCommand
			}
			queueHIDPayload(t, dev, firstCommand, []byte{0xaa})
			if err := awaitHIDResult(t, first); err != nil {
				t.Fatal(err)
			}
			awaitHIDRead(t, dev)
			queueHIDPayload(t, dev, secondCommand, []byte{0xbb})
			if err := awaitHIDResult(t, second); err != nil {
				t.Fatal(err)
			}
			packets := dev.writtenPackets()
			if len(packets) != 2 || packets[0][4] != firstCommand || packets[1][4] != secondCommand {
				t.Fatalf("request ordering = %x", packets)
			}
		})
	}
}

func TestHIDSessionConcurrentCloseInterruptsExchange(t *testing.T) {
	t.Parallel()
	session, dev := newTestHIDSession(t)
	result := make(chan error, 1)
	go func() { _, err := session.ExchangeHID(context.Background(), 0x42, nil); result <- err }()
	awaitHIDRead(t, dev)
	if err := session.Close(); err != nil {
		t.Fatal(err)
	}
	if err := awaitHIDResult(t, result); !errors.Is(err, transport.ErrDisconnected) {
		t.Fatalf("exchange after close = %v", err)
	}
	if err := session.Close(); err != nil {
		t.Fatalf("second close = %v", err)
	}
}
