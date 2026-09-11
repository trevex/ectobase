// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package controllers

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	compiledv1 "github.com/trevex/ectobase/api/compiled/v1alpha1"
	computev1 "github.com/trevex/ectobase/api/compute/v1alpha1"
	netv1 "github.com/trevex/ectobase/api/net/v1alpha1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// OrphanSweeper deletes compiled twins whose source object no longer exists.
//
// The source finalizer is the primary teardown path; this is the backstop for the cases it cannot
// cover — a finalizer force-removed by an operator to unstick a delete, or twins left behind by a
// layout change. It is deliberately conservative: it only touches twins carrying a source
// back-reference (see stampSource) and only after MinAge, so it can never race a twin that was
// just created for a live source.
type OrphanSweeper struct {
	// Client lists and deletes twins (cached reads are fine — a stale twin listing at worst
	// defers a delete to the next tick).
	Client client.Client
	// APIReader resolves the SOURCE object uncached. This must not be the cache: a lagging cache
	// reporting a live source as missing would delete a twin that is still in use.
	APIReader client.Reader
	Interval  time.Duration // sweep cadence; defaults to 10m
	MinAge    time.Duration // ignore twins younger than this; defaults to 5m
}

func (s *OrphanSweeper) defaults() {
	if s.Interval == 0 {
		s.Interval = 10 * time.Minute
	}
	if s.MinAge == 0 {
		s.MinAge = 5 * time.Minute
	}
}

// Start runs the sweep every Interval until ctx is done (manager.Runnable).
func (s *OrphanSweeper) Start(ctx context.Context) error {
	s.defaults()
	t := time.NewTicker(s.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			if n, err := s.SweepOnce(ctx); err != nil {
				slog.Error("compiled orphan sweep", "err", err)
			} else if n > 0 {
				slog.Warn("compiled orphan sweep reclaimed twins whose source was gone", "count", n)
			}
		}
	}
}

// SweepOnce deletes every orphaned twin across all compiled kinds and returns how many it removed.
func (s *OrphanSweeper) SweepOnce(ctx context.Context) (int, error) {
	s.defaults()
	kinds := []struct {
		list   client.ObjectList
		source func() client.Object
	}{
		{&compiledv1.CompiledNICList{}, func() client.Object { return &netv1.NetworkInterface{} }},
		{&compiledv1.CompiledVMList{}, func() client.Object { return &computev1.VirtualMachine{} }},
		{&compiledv1.CompiledContainerList{}, func() client.Object { return &computev1.Container{} }},
		// Attachments are 1:N per VirtualMachine; the stamped source is that VM.
		{&compiledv1.CompiledVolumeAttachmentList{}, func() client.Object { return &computev1.VirtualMachine{} }},
	}
	total := 0
	for _, k := range kinds {
		n, err := s.sweepKind(ctx, k.list, k.source)
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

// sweepKind deletes twins of one kind whose stamped source is gone.
func (s *OrphanSweeper) sweepKind(ctx context.Context, list client.ObjectList, newSource func() client.Object) (int, error) {
	if err := s.Client.List(ctx, list); err != nil {
		return 0, fmt.Errorf("list twins: %w", err)
	}
	items, err := meta.ExtractList(list)
	if err != nil {
		return 0, fmt.Errorf("extract twins: %w", err)
	}
	swept := 0
	for _, item := range items {
		twin, ok := item.(client.Object)
		if !ok {
			continue
		}
		ns, name, stamped := sourceOf(twin)
		if !stamped {
			// No back-reference: either a twin from before this mechanism existed, or one
			// created by something else. We cannot prove it is an orphan, so leave it.
			continue
		}
		if time.Since(twin.GetCreationTimestamp().Time) < s.MinAge {
			continue
		}
		src := newSource()
		err := s.APIReader.Get(ctx, client.ObjectKey{Namespace: ns, Name: name}, src)
		if err == nil {
			continue // source alive
		}
		if !apierrors.IsNotFound(err) {
			return swept, fmt.Errorf("resolve source %s/%s: %w", ns, name, err)
		}
		if err := deleteIfExists(ctx, s.Client, twin); err != nil {
			return swept, fmt.Errorf("delete orphan %s/%s: %w", twin.GetNamespace(), twin.GetName(), err)
		}
		swept++
	}
	return swept, nil
}
