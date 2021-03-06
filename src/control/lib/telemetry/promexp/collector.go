//
// (C) Copyright 2021 Intel Corporation.
//
// SPDX-License-Identifier: BSD-2-Clause-Patent
//
// +build linux,amd64
//

package promexp

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"unicode"

	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/daos-stack/daos/src/control/lib/telemetry"
	"github.com/daos-stack/daos/src/control/logging"
)

type (
	Collector struct {
		log            logging.Logger
		summary        *prometheus.SummaryVec
		ignoredMetrics []*regexp.Regexp
		sources        []*EngineSource
	}

	CollectorOpts struct {
		Ignores []string
	}

	EngineSource struct {
		ctx   context.Context
		Index uint32
		Rank  uint32
	}

	labelMap map[string]string
)

func NewEngineSource(parent context.Context, idx uint32, rank uint32) (*EngineSource, error) {
	ctx, err := telemetry.Init(parent, idx)
	if err != nil {
		return nil, errors.Wrap(err, "failed to init telemetry")
	}

	return &EngineSource{
		ctx:   ctx,
		Index: idx,
		Rank:  rank,
	}, nil
}

func defaultCollectorOpts() *CollectorOpts {
	return &CollectorOpts{}
}

func NewCollector(log logging.Logger, opts *CollectorOpts, sources ...*EngineSource) (*Collector, error) {
	if len(sources) == 0 {
		return nil, errors.New("Collector must have > 0 sources")
	}

	if opts == nil {
		opts = defaultCollectorOpts()
	}

	c := &Collector{
		log:     log,
		sources: sources,
		summary: prometheus.NewSummaryVec(
			prometheus.SummaryOpts{
				Namespace: "engine",
				Subsystem: "exporter",
				Name:      "scrape_duration_seconds",
				Help:      "daos_exporter: Duration of a scrape job.",
			},
			[]string{"source", "result"},
		),
	}

	for _, pat := range opts.Ignores {
		re, err := regexp.Compile(pat)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to compile %q", pat)
		}
		c.ignoredMetrics = append(c.ignoredMetrics, re)
	}

	return c, nil
}

func fixPath(in string) (labels labelMap, name string) {
	name = strings.Map(func(r rune) rune {
		if !unicode.IsPrint(r) || unicode.IsSpace(r) {
			return '_'
		}
		switch r {
		case '/', ':':
			return '_'
		}

		return r
	}, strings.TrimLeft(in, "/"))

	labels = make(labelMap)
	ID_re := regexp.MustCompile(`ID_(\d+)_`)
	io_re := regexp.MustCompile(`io_(\d+)_`)

	name = ID_re.ReplaceAllString(name, "")
	io_matches := io_re.FindStringSubmatch(name)
	if len(io_matches) > 0 {
		labels["target"] = io_matches[1]
		name = io_re.ReplaceAllString(name, "io_")
	}

	return
}

func (es *EngineSource) Collect(log logging.Logger, ch chan<- *rankMetric) {
	metrics := make(chan telemetry.Metric)
	go func() {
		if err := telemetry.CollectMetrics(es.ctx, "", metrics); err != nil {
			log.Errorf("failed to collect metrics for engine rank %d: %s", es.Rank, err)
			return
		}
	}()

	for metric := range metrics {
		ch <- &rankMetric{
			r: es.Rank,
			m: metric,
		}
	}
}

type rankMetric struct {
	r uint32
	m telemetry.Metric
}

func (c *Collector) isIgnored(name string) bool {
	for _, re := range c.ignoredMetrics {
		if re.MatchString(name) {
			return true
		}
	}

	return false
}

func (lm labelMap) keys() (keys []string) {
	for label := range lm {
		keys = append(keys, label)
	}

	return
}

type gvMap map[string]*prometheus.GaugeVec

func (m gvMap) add(name, help string, value float64, labels labelMap) {
	var gv *prometheus.GaugeVec
	var found bool

	gv, found = m[name]
	if !found {
		gv = prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: name,
			Help: help,
		}, labels.keys())
		m[name] = gv
	}
	gv.With(prometheus.Labels(labels)).Set(value)
}

type cvMap map[string]*prometheus.CounterVec

func (m cvMap) add(name, help string, value float64, labels labelMap) {
	var cv *prometheus.CounterVec
	var found bool

	cv, found = m[name]
	if !found {
		cv = prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: name,
			Help: help,
		}, labels.keys())
		m[name] = cv
	}
	cv.With(prometheus.Labels(labels)).Add(value)
}

type metricStat struct {
	name  string
	desc  string
	value float64
}

func getMetricStats(baseName, shortDesc string, m telemetry.Metric) (stats []*metricStat) {
	ms, ok := m.(telemetry.StatsMetric)
	if !ok {
		return
	}

	if ms.SampleSize() == 0 {
		return
	}

	for name, s := range map[string]struct {
		fn   func() float64
		desc string
	}{
		"min": {
			fn:   ms.FloatMin,
			desc: " (min value)",
		},
		"max": {
			fn:   ms.FloatMax,
			desc: " (max value)",
		},
		"mean": {
			fn:   ms.Mean,
			desc: " (mean)",
		},
		"stddev": {
			fn:   ms.StdDev,
			desc: " (std dev)",
		},
	} {
		stats = append(stats, &metricStat{
			name:  baseName + "_" + name,
			desc:  shortDesc + s.desc,
			value: s.fn(),
		})
	}

	return
}

func (c *Collector) Collect(ch chan<- prometheus.Metric) {
	rankMetrics := make(chan *rankMetric)
	go func(sources []*EngineSource) {
		for _, source := range c.sources {
			source.Collect(c.log, rankMetrics)
		}
		close(rankMetrics)
	}(c.sources)

	gauges := make(gvMap)
	counters := make(cvMap)

	for rm := range rankMetrics {
		labels, path := fixPath(rm.m.Path())
		labels["rank"] = fmt.Sprintf("%d", rm.r)

		baseName := prometheus.BuildFQName("engine", path, rm.m.Name())
		shortDesc := rm.m.ShortDesc()

		switch rm.m.Type() {
		case telemetry.MetricTypeGauge:
			if c.isIgnored(baseName) {
				continue
			}

			gauges.add(baseName, shortDesc, rm.m.FloatValue(), labels)
			for _, ms := range getMetricStats(baseName, shortDesc, rm.m) {
				gauges.add(ms.name, ms.desc, ms.value, labels)
			}
		case telemetry.MetricTypeCounter:
			if c.isIgnored(baseName) {
				break
			}

			counters.add(baseName, shortDesc, rm.m.FloatValue(), labels)
		default:
			c.log.Errorf("metric type %d not supported", rm.m.Type())
		}
	}

	for _, gv := range gauges {
		gv.Collect(ch)
	}
	for _, cv := range counters {
		cv.Collect(ch)
	}
}

func (c *Collector) Describe(ch chan<- *prometheus.Desc) {
	c.summary.Describe(ch)
}
